/* SPDX-License-Identifier: MIT */
/* Native macOS reference probe; never a claim about WindowServer on A16. */
#include <OpenGL/OpenGL.h>
#include <OpenGL/CGLRenderers.h>
#include <OpenGL/gl.h>
#include <OpenGL/glext.h>
#include <stdio.h>

int main(void)
{
    CGLRendererInfoObj info=0;GLint count=0;
    CGLError error=CGLQueryRendererInfo(0xffffffff,&info,&count);
    printf("renderer_query=%d count=%d\n",error,count);
    if(!error)for(GLint i=0;i<count;i++) {
        GLint id=0,accelerated=0,online=0;
        CGLDescribeRenderer(info,i,kCGLRPRendererID,&id);
        CGLDescribeRenderer(info,i,kCGLRPAccelerated,&accelerated);
        CGLDescribeRenderer(info,i,kCGLRPOnline,&online);
        printf("renderer[%d] id=0x%x accelerated=%d online=%d\n",i,id,accelerated,online);
    }
    if(info)CGLDestroyRendererInfo(info);
    CGLPixelFormatAttribute attrs[]={kCGLPFARendererID,
        (CGLPixelFormatAttribute)kCGLRendererGenericFloatID,kCGLPFAAllowOfflineRenderers,0};
    CGLPixelFormatObj format=0;CGLContextObj context=0;
    error=CGLChoosePixelFormat(attrs,&format,&count);
    printf("software_choose=%d formats=%d requested=0x%x\n",error,count,kCGLRendererGenericFloatID);
    if(error || !format)return 0;
    error=CGLCreateContext(format,0,&context);
    CGLDestroyPixelFormat(format);
    printf("software_context=%d\n",error);
    if(error || !context)return 0;
    CGLSetCurrentContext(context);
    GLint id=0;CGLGetParameter(context,kCGLCPCurrentRendererID,&id);
    printf("actual_renderer=0x%x name=%s version=%s\n",id,glGetString(GL_RENDERER),glGetString(GL_VERSION));
    GLuint texture=0,fbo=0;unsigned char pixel[4]={0},triangle[4]={0};
    glGenTextures(1,&texture);glBindTexture(GL_TEXTURE_2D,texture);
    glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA8,4,4,0,GL_RGBA,GL_UNSIGNED_BYTE,0);
    glGenFramebuffersEXT(1,&fbo);glBindFramebufferEXT(GL_FRAMEBUFFER_EXT,fbo);
    glFramebufferTexture2DEXT(GL_FRAMEBUFFER_EXT,GL_COLOR_ATTACHMENT0_EXT,GL_TEXTURE_2D,texture,0);
    GLenum status=glCheckFramebufferStatusEXT(GL_FRAMEBUFFER_EXT);
    if(status==GL_FRAMEBUFFER_COMPLETE_EXT) {
        glViewport(0,0,4,4);glClearColor(0.25f,0.5f,0.75f,1.0f);glClear(GL_COLOR_BUFFER_BIT);
        glReadPixels(0,0,1,1,GL_RGBA,GL_UNSIGNED_BYTE,pixel);
        glColor4ub(255,0,0,255);glBegin(GL_TRIANGLES);
        glVertex2f(-1,-1);glVertex2f(1,-1);glVertex2f(0,1);glEnd();
        glReadPixels(2,1,1,1,GL_RGBA,GL_UNSIGNED_BYTE,triangle);
    }
    printf("fbo_status=0x%x gl_error=0x%x pixel=%u,%u,%u,%u\n",status,glGetError(),
           pixel[0],pixel[1],pixel[2],pixel[3]);
    printf("triangle_pixel=%u,%u,%u,%u\n",triangle[0],triangle[1],triangle[2],triangle[3]);
    glDeleteFramebuffersEXT(1,&fbo);glDeleteTextures(1,&texture);
    CGLSetCurrentContext(0);CGLDestroyContext(context);
    return 0;
}
