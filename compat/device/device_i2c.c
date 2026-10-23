/* SPDX-License-Identifier: MIT */
/* The I2C controller model and device interrupt routing.
 * Part of compat/device.c's translation unit, included in order; not compiled on its own. */
static int i2c_valid(const struct device_i2c_empty *s)
{
    return s && s->ready==1 && s->tx_count<=DEVICE_I2C_FIFO_WORDS &&
        s->blocked<=1 && s->halt<=1 && !(s->status&~I2C_FLAGS) &&
        (!s->tx_count || s->blocked ||
         ((s->tx[0]&0x100) && !(s->tx[0]&~0x3ffU))) &&
        (!s->shadow_command || s->shadow_command==0x100000) &&
        !(s->control&~(I2C_CONTROL&~0x600U)) && !(s->address&~0x80000000U);
}

static uint32_t i2c_status(const struct device_i2c_empty *s)
{
    /* Empty slave TX, actual master FIFO levels, idle high SDA/SCL when
     * debug sensing is enabled. An ended transaction can still be a NACK. */
    return s->status | (1U<<8) | (s->tx_count ? 0 : 1U<<16) |
        (s->tx_count==DEVICE_I2C_FIFO_WORDS ? 1U<<17 : 0) |
        (s->address ? 0x18U : 0);
}

static void i2c_run(struct device_i2c_empty *s)
{
    if (s->halt || !(s->control&0x800) || s->blocked || !s->tx_count) return;
    /* HALT permits the driver to prefill a transaction before execution.
     * The first address encounters an empty bus and gets a NACK. Consume
     * that word only; later commands remain queued until a TX reset. */
    s->last_address=s->tx[0]&0xff;
    for (unsigned i=1;i<s->tx_count;i++) s->tx[i-1]=s->tx[i];
    s->tx[--s->tx_count]=0;
    s->status|=I2C_FLAGS;
    s->blocked=1;
    s->nacks++;
}

static int device_has_irq(const struct device_model *model)
{
    return model->kind == DEVICE_SPMI_GEN3_EMPTY_V1 || model->kind == DEVICE_SPMI_PMU_RTC_V1 || model->kind == DEVICE_DOCK_FIFO_V1 ||
           model->kind == DEVICE_DART_T8110_V1 || model->kind == DEVICE_I2C_EMPTY_V1 ||
           model->kind == DEVICE_AES_SOFTWARE_V1 ||
           (model->kind == DEVICE_SEP_ASC_MAILBOX_V1 && model->config[1]);
}

enum device_result device_models_route_irqs(const struct device_model *models,
    struct device_state *states, unsigned count)
{
    if (count > DEVICE_MODEL_MAX || (count && (!models || !states))) return DEVICE_BAD_CONFIG;
    int aic=-1; unsigned sources=0;
    for (unsigned i=0; i<count; i++) {
        if (!valid(&models[i])) return DEVICE_BAD_CONFIG;
        if (models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 &&
            !sep_asc_valid(&states[i].sep_asc,(unsigned)models[i].config[1]))
            return DEVICE_BAD_CONFIG;
        if (models[i].kind==DEVICE_I2C_EMPTY_V1 && !i2c_valid(&states[i].i2c))
            return DEVICE_BAD_CONFIG;
        if (models[i].kind==DEVICE_AES_SOFTWARE_V1 &&
            (states[i].aes.ready!=1 || (states[i].aes.irq_status&~0x20U) ||
             (states[i].aes.irq_enable&~0x3efffU))) return DEVICE_BAD_CONFIG;
        if (models[i].kind == DEVICE_AIC3_FLAT_V1) {
            if (aic >= 0) return DEVICE_BAD_CONFIG;
            aic=(int)i;
        }
        sources += device_has_irq(&models[i]);
    }
    if (!sources) return DEVICE_OK;
    if (aic < 0) return DEVICE_BAD_CONFIG;
    for (unsigned i=0; i<count; i++)
        if (device_has_irq(&models[i]) &&
            (models[i].config[2] >= models[aic].config[0] ||
             (models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 &&
              models[i].config[3] >= models[aic].config[0]))) return DEVICE_BAD_CONFIG;
    for (unsigned i=0; i<count; i++) if (device_has_irq(&models[i])) {
      unsigned lanes=models[i].kind==DEVICE_SEP_ASC_MAILBOX_V1 ? 2 : 1;
      for (unsigned lane=0;lane<lanes;lane++) {
        unsigned irq=(unsigned)models[i].config[2+lane];
        int level=0;
        for (unsigned j=0; j<count; j++) {
            if (!device_has_irq(&models[j])) continue;
            if (models[j].kind==DEVICE_SEP_ASC_MAILBOX_V1) {
                if (models[j].config[2]==irq)
                    level |= !!(states[j].sep_asc.enable[1] && states[j].sep_asc.reply_count);
                if (models[j].config[3]==irq)
                    level |= !!(states[j].sep_asc.enable[0] && !states[j].sep_asc.count);
                continue;
            }
            if (models[j].config[2]!=irq) continue;
            if (models[j].kind == DEVICE_SPMI_GEN3_EMPTY_V1 || models[j].kind == DEVICE_SPMI_PMU_RTC_V1)
                for (unsigned k=0; k<9; k++)
                    level |= !!(states[j].spmi.flags[k] & states[j].spmi.enable[k]);
            else if (models[j].kind == DEVICE_DART_T8110_V1)
                level |= dart_irq_pending(&states[j].dart);
            else if (models[j].kind == DEVICE_AES_SOFTWARE_V1)
                level |= !!(states[j].aes.irq_status&states[j].aes.irq_enable);
            else if (models[j].kind == DEVICE_I2C_EMPTY_V1) {
                if (!i2c_valid(&states[j].i2c)) return DEVICE_BAD_CONFIG;
                level |= !!(i2c_status(&states[j].i2c)&states[j].i2c.mask);
            }
            else level |= !!((states[j].dockfifo.flags | dockfifo_level(&states[j])) &
                             states[j].dockfifo.mask);
        }
        device_irq_set_level(&models[aic],&states[aic],irq,level);
      }
    }
    return DEVICE_OK;
}
