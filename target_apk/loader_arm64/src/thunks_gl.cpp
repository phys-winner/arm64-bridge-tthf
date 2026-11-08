// SPDX-License-Identifier: GPL-3.0-or-later
#include "thunk_manager.h"
#include "dynarmic_host.h"
#include "thunk_types.h"
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <android/log.h>
#include <vector>
#include <cstring>
#include <unordered_map>

// OES extension entry points not exported by the android-26 NDK headers
extern "C" {
void* glMapBufferOES(GLenum target, GLenum access);
GLboolean glUnmapBufferOES(GLenum target);
void glGetProgramBinaryOES(GLuint program, GLsizei bufSize, GLsizei* length, GLenum* binaryFormat, void* binary);
void glProgramBinaryOES(GLuint program, GLenum binaryFormat, const void* binary, GLint length);
}

#define LOG_TAG "GOF2_GLThunks"
#include "bridge_logging.h"

static uint32_t g_draw_calls = 0;

void ThunkManager::RegisterGLThunks() {
    uint8_t* mem = m_host.GetGuestMemoryBase();

    RegisterThunk("glActiveTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glActiveTexture(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glAttachShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glAttachShader(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glBindBuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindBuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindFramebuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindFramebuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindRenderbuffer(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBindTexture", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBindTexture(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glBlendFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendFunc(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glBufferData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        GLsizeiptr size = static_cast<GLsizeiptr>(jit.Regs()[1]);
        const void* data = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]);
        GLenum usage = static_cast<GLenum>(jit.Regs()[3]);
        glBufferData(target, size, data, usage);
    });

    RegisterThunk("glCheckFramebufferStatus", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCheckFramebufferStatus(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glClear", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static uint32_t clear_count = 0;
        if (++clear_count <= 5 || clear_count % 120 == 0) {
            if (clear_count < 4) LOGI("glClear: mask=0x%08X (count=%u)", jit.Regs()[0], clear_count);
        }
        glClear(static_cast<GLbitfield>(jit.Regs()[0]));
    });

    RegisterThunk("glClearColor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float r = ReadSF(jit, 0);
        float g = ReadSF(jit, 1);
        float b = ReadSF(jit, 2);
        float a = ReadSF(jit, 3);
        glClearColor(r, g, b, a);
    });

    RegisterThunk("glColorMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glColorMask(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glCompileShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint shader = jit.Regs()[0];
        glCompileShader(shader);
        GLint compiled = 0;
        glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
        if (!compiled) {
            char log[1024];
            glGetShaderInfoLog(shader, sizeof(log), nullptr, log);
            LOGE("Shader %u compile failed: %s", shader, log);
        }
    });

    RegisterThunk("glCompressedTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = jit.Regs()[0];
        GLint level = jit.Regs()[1];
        GLenum internalformat = jit.Regs()[2];
        GLsizei width = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei height = host.MemoryRead32(sp);
        GLint border = host.MemoryRead32(sp + 4);
        GLsizei imageSize = host.MemoryRead32(sp + 8);
        const void* data = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 12));
        glCompressedTexImage2D(target, level, internalformat, width, height, border, imageSize, data);
    });

    RegisterThunk("glCreateProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateProgram();
    });

    RegisterThunk("glCreateShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glCreateShader(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glCullFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glCullFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDeleteBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteBuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteFramebuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteProgram(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteRenderbuffers(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDeleteShader", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteShader(jit.Regs()[0]);
    });

    RegisterThunk("glDeleteTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDeleteTextures(jit.Regs()[0], reinterpret_cast<const GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glDepthFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthFunc(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDepthMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDepthMask(static_cast<GLboolean>(jit.Regs()[0]));
    });

    RegisterThunk("glDisable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glDisableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glDisableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glDrawArrays", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        if (++g_draw_calls < 4) {
            LOGI("glDrawArrays called (mode=%u, first=%d, count=%d)", jit.Regs()[0], (int)jit.Regs()[1], (int)jit.Regs()[2]);
        }
        glDrawArrays(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLint>(jit.Regs()[1]), static_cast<GLsizei>(jit.Regs()[2]));
    });

    RegisterThunk("glDrawElements", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t indices_gaddr = jit.Regs()[3];
        GLint bound_elem_buf = 0;
        glGetIntegerv(GL_ELEMENT_ARRAY_BUFFER_BINDING, &bound_elem_buf);
        const void* indices = (bound_elem_buf != 0) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(indices_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), indices_gaddr);
        if (++g_draw_calls < 4) {
            LOGI("glDrawElements called (mode=%u, count=%d, type=%u, indices=0x%X, bound_buf=%d)",
                 jit.Regs()[0], (int)jit.Regs()[1], jit.Regs()[2], indices_gaddr, bound_elem_buf);
        }
        glDrawElements(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLsizei>(jit.Regs()[1]),
                       static_cast<GLenum>(jit.Regs()[2]), indices);
    });

    RegisterThunk("glEnable", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnable(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glEnableVertexAttribArray", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glEnableVertexAttribArray(jit.Regs()[0]);
    });

    RegisterThunk("glFlush", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFlush();
    });

    RegisterThunk("glFramebufferRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferRenderbuffer(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glFramebufferTexture2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFramebufferTexture2D(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], host.MemoryRead32(jit.Regs()[13]));
    });

    RegisterThunk("glFrontFace", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glFrontFace(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGenBuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenBuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenFramebuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenFramebuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenRenderbuffers", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenRenderbuffers(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenTextures", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenTextures(jit.Regs()[0], reinterpret_cast<GLuint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGenerateMipmap", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGenerateMipmap(static_cast<GLenum>(jit.Regs()[0]));
    });

    RegisterThunk("glGetActiveAttrib", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei* length = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        GLint* size = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        GLenum* type = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 4)));
        GLchar* name = reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8)));
        glGetActiveAttrib(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], length, size, type, name);
    });

    RegisterThunk("glGetActiveUniform", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei* length = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        GLint* size = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp)));
        GLenum* type = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 4)));
        GLchar* name = reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8)));
        glGetActiveUniform(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], length, size, type, name);
    });

    RegisterThunk("glGetAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glGetAttribLocation(jit.Regs()[0], reinterpret_cast<const GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGetError", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glGetError();
    });

    RegisterThunk("glGetIntegerv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetIntegerv(static_cast<GLenum>(jit.Regs()[0]),
                      reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glGetProgramInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* length = jit.Regs()[2] ?
            reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])) : nullptr;
        glGetProgramInfoLog(jit.Regs()[0], jit.Regs()[1], length,
                           reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glGetProgramiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetProgramiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]),
                       reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetRenderbufferParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetRenderbufferParameteriv(jit.Regs()[0], jit.Regs()[1],
                                     reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetShaderInfoLog", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* length = jit.Regs()[2] ?
            reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])) : nullptr;
        glGetShaderInfoLog(jit.Regs()[0], jit.Regs()[1], length,
                          reinterpret_cast<GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glGetShaderiv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glGetShaderiv(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]),
                      reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glGetString", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const GLubyte* str = glGetString(static_cast<GLenum>(jit.Regs()[0]));
        if (!str) {
            jit.Regs()[0] = 0;
            return;
        }
        uint32_t guest_addr = host.GuestAlloc(strlen(reinterpret_cast<const char*>(str)) + 1);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + guest_addr), reinterpret_cast<const char*>(str));
        jit.Regs()[0] = guest_addr;
    });

    RegisterThunk("glGetUniformLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glGetUniformLocation(jit.Regs()[0], reinterpret_cast<const GLchar*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1])));
    });

    RegisterThunk("glHint", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glHint(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]));
    });

    RegisterThunk("glLineWidth", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glLineWidth(ReadSF(jit, 0));
    });

    RegisterThunk("glLinkProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint prog = jit.Regs()[0];
        glLinkProgram(prog);
        GLint linked = 0;
        glGetProgramiv(prog, GL_LINK_STATUS, &linked);
        if (!linked) {
            char log[1024];
            glGetProgramInfoLog(prog, sizeof(log), nullptr, log);
            LOGE("Program %u link failed: %s", prog, log);
        }
    });

    RegisterThunk("glPixelStorei", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPixelStorei(static_cast<GLenum>(jit.Regs()[0]), jit.Regs()[1]);
    });

    RegisterThunk("glPolygonOffset", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glPolygonOffset(*reinterpret_cast<float*>(&jit.Regs()[0]), *reinterpret_cast<float*>(&jit.Regs()[1]));
    });

    RegisterThunk("glReadPixels", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLenum format = host.MemoryRead32(sp);
        GLenum type = host.MemoryRead32(sp + 4);
        void* pixels = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8));
        glReadPixels(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3], format, type, pixels);
    });

    RegisterThunk("glRenderbufferStorage", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glRenderbufferStorage(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glScissor", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glScissor(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    RegisterThunk("glShaderSource", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint shader = jit.Regs()[0];
        GLsizei count = jit.Regs()[1];
        uint32_t str_array_gaddr = jit.Regs()[2];
        uint32_t len_array_gaddr = jit.Regs()[3];

        std::vector<const char*> strings(count);
        for (GLsizei i = 0; i < count; ++i) {
            uint32_t str_gaddr = host.MemoryRead32(str_array_gaddr + i * 4);
            strings[i] = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), str_gaddr));
        }

        const GLint* lengths = len_array_gaddr ?
            reinterpret_cast<const GLint*>(GuestToHost(host.GetGuestMemoryBase(), len_array_gaddr)) : nullptr;

        glShaderSource(shader, count, strings.data(), lengths);
    });

    RegisterThunk("glTexImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = jit.Regs()[0];
        GLint level = jit.Regs()[1];
        GLint internalformat = jit.Regs()[2];
        GLsizei width = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei height = host.MemoryRead32(sp);
        GLint border = host.MemoryRead32(sp + 4);
        GLenum format = host.MemoryRead32(sp + 8);
        GLenum type = host.MemoryRead32(sp + 12);
        uint32_t pixels_gaddr = host.MemoryRead32(sp + 16);
        const void* pixels = (pixels_gaddr < 0x10000) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(pixels_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), pixels_gaddr);
        glTexImage2D(target, level, internalformat, width, height, border, format, type, pixels);
    });

    RegisterThunk("glTexParameterf", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameterf(jit.Regs()[0], jit.Regs()[1], ReadSF(jit, 2));
    });

    RegisterThunk("glTexParameteri", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glTexParameteri(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2]);
    });

    RegisterThunk("glUniform1f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1f(jit.Regs()[0], ReadSF(jit, 1));
    });

    RegisterThunk("glUniform1i", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1i(jit.Regs()[0], jit.Regs()[1]);
    });

    RegisterThunk("glUniform2f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform2f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2));
    });

    RegisterThunk("glUniform3f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2), ReadSF(jit, 3));
    });

    RegisterThunk("glUniform3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform3fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glUniform4f", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        // softfp: loc=r0, v0..v2 = r1..r3, v3 spills to the guest stack
        glUniform4f(jit.Regs()[0], ReadSF(jit, 1), ReadSF(jit, 2), ReadSF(jit, 3),
                    ReadStackF(jit, host.GetGuestMemoryBase(), 0));
    });

    RegisterThunk("glUniform4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform4fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    RegisterThunk("glUniformMatrix3fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniformMatrix3fv(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                           reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glUniformMatrix4fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniformMatrix4fv(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2],
                           reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3])));
    });

    RegisterThunk("glUseProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUseProgram(jit.Regs()[0]);
    });

    RegisterThunk("glVertexAttribPointer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLuint index = jit.Regs()[0];
        GLint size = jit.Regs()[1];
        GLenum type = jit.Regs()[2];
        GLboolean normalized = jit.Regs()[3];
        uint32_t sp = jit.Regs()[13];
        GLsizei stride = host.MemoryRead32(sp);
        uint32_t ptr_gaddr = host.MemoryRead32(sp + 4);

        GLint bound_buf = 0;
        glGetIntegerv(GL_ARRAY_BUFFER_BINDING, &bound_buf);
        const void* ptr = (bound_buf != 0) ?
            reinterpret_cast<const void*>(static_cast<uintptr_t>(ptr_gaddr)) :
            GuestToHost(host.GetGuestMemoryBase(), ptr_gaddr);

        glVertexAttribPointer(index, size, type, normalized, stride, ptr);
    });

    RegisterThunk("glViewport", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        static uint32_t vp_n = 0;
        if (++vp_n < 4)
            LOGI("glViewport(%d,%d,%d,%d)", (int)jit.Regs()[0], (int)jit.Regs()[1],
                 (int)jit.Regs()[2], (int)jit.Regs()[3]);
        glViewport(jit.Regs()[0], jit.Regs()[1], jit.Regs()[2], jit.Regs()[3]);
    });

    // -------------------------------------------------------------
    // Tiny Thief additions
    // -------------------------------------------------------------
    RegisterThunk("glBindAttribLocation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const char* name = reinterpret_cast<const char*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        glBindAttribLocation(jit.Regs()[0], jit.Regs()[1], name);
    });
    RegisterThunk("glBlendEquation", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendEquation(static_cast<GLenum>(jit.Regs()[0]));
    });
    RegisterThunk("glBlendFuncSeparate", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glBlendFuncSeparate(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]),
                            static_cast<GLenum>(jit.Regs()[2]), static_cast<GLenum>(jit.Regs()[3]));
    });
    RegisterThunk("glBufferSubData", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* data = GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]);
        uint32_t sp = jit.Regs()[13];
        glBufferSubData(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLintptr>(jit.Regs()[1]),
                        static_cast<GLsizeiptr>(host.MemoryRead32(sp)), data);
    });
    RegisterThunk("glClearStencil", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glClearStencil(static_cast<GLint>(jit.Regs()[0]));
    });
    RegisterThunk("glFinish", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) { glFinish(); });
    RegisterThunk("glGetFloatv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        float* out = reinterpret_cast<float*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[1]));
        glGetFloatv(static_cast<GLenum>(jit.Regs()[0]), out);
    });
    RegisterThunk("glGetFramebufferAttachmentParameteriv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLint* out = reinterpret_cast<GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        glGetFramebufferAttachmentParameteriv(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]),
                                              static_cast<GLenum>(jit.Regs()[2]), out);
    });
    RegisterThunk("glIsEnabled", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glIsEnabled(static_cast<GLenum>(jit.Regs()[0]));
    });
    RegisterThunk("glIsFramebuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glIsFramebuffer(jit.Regs()[0]);
    });
    RegisterThunk("glIsProgram", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glIsProgram(jit.Regs()[0]);
    });
    RegisterThunk("glIsRenderbuffer", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        jit.Regs()[0] = glIsRenderbuffer(jit.Regs()[0]);
    });
    RegisterThunk("glReleaseShaderCompiler", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glReleaseShaderCompiler();
    });
    RegisterThunk("glStencilFunc", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glStencilFunc(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLint>(jit.Regs()[1]), jit.Regs()[2]);
    });
    RegisterThunk("glStencilMask", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glStencilMask(jit.Regs()[0]);
    });
    RegisterThunk("glStencilOp", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glStencilOp(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLenum>(jit.Regs()[1]), static_cast<GLenum>(jit.Regs()[2]));
    });
    RegisterThunk("glTexSubImage2D", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t sp = jit.Regs()[13];
        GLsizei w = host.MemoryRead32(sp);
        GLsizei h = host.MemoryRead32(sp + 4);
        const void* px = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(sp + 8));
        glTexSubImage2D(static_cast<GLenum>(jit.Regs()[0]), static_cast<GLint>(jit.Regs()[1]),
                        static_cast<GLint>(jit.Regs()[2]), static_cast<GLint>(jit.Regs()[3]),
                        w, h, static_cast<GLenum>(host.MemoryRead32(sp + 12)),
                        static_cast<GLenum>(host.MemoryRead32(sp + 16)), px);
    });
    RegisterThunk("glUniform1fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });
    RegisterThunk("glUniform1iv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform1iv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLint*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });
    RegisterThunk("glUniform2fv", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        glUniform2fv(jit.Regs()[0], jit.Regs()[1],
                     reinterpret_cast<const GLfloat*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2])));
    });

    // OES_mapbuffer / OES_get_program_binary: guest can't see host pointers,
    // so shadow the mapped region in guest memory and sync on unmap.
    static std::unordered_map<uint32_t, std::pair<void*, uint32_t>> g_gl_maps; // guest ptr -> (host ptr, size)
    RegisterThunk("glMapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLenum target = static_cast<GLenum>(jit.Regs()[0]);
        void* host_ptr = glMapBufferOES(target, GL_WRITE_ONLY_OES);
        if (!host_ptr) { jit.Regs()[0] = 0; return; }
        GLint size = 0;
        glGetBufferParameteriv(target, GL_BUFFER_SIZE, &size);
        uint32_t guest_ptr = host.GuestAlloc(size, 16);
        memcpy(host.GetGuestMemoryBase() + guest_ptr, host_ptr, size);
        g_gl_maps[guest_ptr] = {host_ptr, static_cast<uint32_t>(size)};
        jit.Regs()[0] = guest_ptr;
    });
    RegisterThunk("glUnmapBufferOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        uint32_t guest_ptr = jit.Regs()[1];
        auto it = g_gl_maps.find(guest_ptr);
        if (it != g_gl_maps.end()) {
            memcpy(it->second.first, host.GetGuestMemoryBase() + guest_ptr, it->second.second);
            g_gl_maps.erase(it);
        }
        jit.Regs()[0] = glUnmapBufferOES(static_cast<GLenum>(jit.Regs()[0]));
    });
    RegisterThunk("glGetProgramBinaryOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        GLsizei* len = reinterpret_cast<GLsizei*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[2]));
        GLenum* fmt = reinterpret_cast<GLenum*>(GuestToHost(host.GetGuestMemoryBase(), jit.Regs()[3]));
        void* bin = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(jit.Regs()[13]));
        glGetProgramBinaryOES(jit.Regs()[0], jit.Regs()[1], len, fmt, bin);
    });
    RegisterThunk("glProgramBinaryOES", [](Dynarmic::A32::Jit& jit, DynarmicHost& host) {
        const void* bin = GuestToHost(host.GetGuestMemoryBase(), host.MemoryRead32(jit.Regs()[13] + 4));
        glProgramBinaryOES(jit.Regs()[0], static_cast<GLenum>(jit.Regs()[1]), bin,
                           static_cast<GLint>(jit.Regs()[2]));
    });
}
