#ifdef _WIN32
#include <stdio.h>
#include <io.h>

#ifdef __cplusplus
extern "C" {
#endif

int OPENSSL_Applink(void) { return 0; }

FILE *OPENSSL_fopen(const char *filename, const char *mode) {
    return fopen(filename, mode);
}

size_t OPENSSL_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fread(ptr, size, nmemb, stream);
}

size_t OPENSSL_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    return fwrite(ptr, size, nmemb, stream);
}

int OPENSSL_fclose(FILE *stream) {
    return fclose(stream);
}

int OPENSSL_fseek(FILE *stream, long offset, int whence) {
    return fseek(stream, offset, whence);
}

long OPENSSL_ftell(FILE *stream) {
    return ftell(stream);
}

int OPENSSL_feof(FILE *stream) {
    return feof(stream);
}

int OPENSSL_ferror(FILE *stream) {
    return ferror(stream);
}

void OPENSSL_clearerr(FILE *stream) {
    clearerr(stream);
}

int OPENSSL_fileno(FILE *stream) {
    return _fileno(stream);
}

void OPENSSL_rewind(FILE *stream) {
    rewind(stream);
}

int OPENSSL_setmode(int fd, int mode) {
    return _setmode(fd, mode);
}

int OPENSSL_getmode(FILE *fp, int *mode) {
    return _getmode(_fileno(fp), mode);
}

#ifdef __cplusplus
}
#endif
#endif
