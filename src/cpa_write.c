#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

/**
 * Given a filename to write in (must not exist), inserts buffer
 * @param target
 * @param buffer
 */
uint8_t write_to_target( char *target, char *buffer) {

    int fd = open(target, O_CREAT|O_EXCL|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);

    if( fd == -1 ){
        if( errno == EEXIST)
            perror("[ERROR] Destination file already exists.");
        else
            perror("[ERROR] target file.");

        return 1;
    }

    size_t length = strlen(buffer);

    write(fd, buffer, length);
    close(fd);

    return 0;
}