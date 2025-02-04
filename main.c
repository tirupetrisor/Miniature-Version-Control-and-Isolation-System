#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>

#define SIZE 1024

int count_file;

// Function to move a potentially dangerous file to the isolation directory
void move_file(const char* file_path, const char* isolated_directory)
{
    char new_path[PATH_MAX];
    snprintf(new_path, sizeof(new_path), "%s/%s", isolated_directory, strrchr(file_path, '/') + 1);

    if (rename(file_path, new_path) == -1)
    {
        perror("Error moving dangerous file\n");
        exit(0);
    }
}

// Function to process files with no permissions: creates a pipe and process,
// communicates the result of the script through the pipe
void process_dangerous_file(const char* file_path, int fd, const char* isolated_directory)
{
    int pfd[2];
    if (pipe(pfd) == -1)
    {
        perror("Error creating pipe\n");
        exit(6);
    }

    int wstatus;
    pid_t w;
    pid_t cpid = fork();

    if (cpid == -1)
    {
        perror("Error during fork\n");
        exit(3);
    }

    if (cpid == 0)
    {
        close(pfd[0]);
        dup2(pfd[1], 1);
        close(pfd[1]);

        execlp("./path to bash", "path to bash", file_path, isolated_directory, NULL);
        perror("Error executing script\n");
        exit(5);
    }
    else
    {
        close(pfd[1]);
        char buffer[SIZE];
        ssize_t nr_bytes = read(pfd[0], buffer, SIZE);
        close(pfd[0]);

        if (nr_bytes > 0)
        {
            buffer[nr_bytes] = '\0';
            if (strcmp(buffer, "SAFE") != 0)
            {
                move_file(file_path, isolated_directory);
                count_file++;
            }
        }

        w = wait(&wstatus);
        if (w == -1)
        {
            perror("Error during wait\n");
            exit(4);
        }
    }
}

// Function to recursively generate the content of a directory
void generate_snapshot(const char* directory, int fd, const char* isolated_directory)
{
    DIR* dir = opendir(directory);
    if (dir == NULL)
    {
        perror("Error opening directory\n");
        exit(1);
    }

    struct dirent* buffer;
    while ((buffer = readdir(dir)) != NULL)
    {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", directory, buffer->d_name);

        if (strcmp(buffer->d_name, ".") == 0 || strcmp(buffer->d_name, "..") == 0)
        {
            continue;
        }

        struct stat file;
        if (lstat(path, &file) == -1)
        {
            perror("Error using lstat\n");
            exit(2);
        }

        char aux[PATH_MAX + 100];
        snprintf(aux, sizeof(aux), "%s/", directory);
        write(fd, aux, strlen(aux));

        if (S_ISDIR(file.st_mode))
        {
            snprintf(aux, sizeof(aux), "%s (DIR) Size: %ld bytes, Inode: %lu, Last modified: %s", buffer->d_name, file.st_size, file.st_ino, ctime(&file.st_mtime));
            write(fd, aux, strlen(aux));
            generate_snapshot(path, fd, isolated_directory);
        }
        if (S_ISREG(file.st_mode))
        {
            if ((file.st_mode & S_IRWXU) == 0 && (file.st_mode & S_IRWXG) == 0 && (file.st_mode & S_IRWXO) == 0)
            {
                process_dangerous_file(path, fd, isolated_directory);
            }
            snprintf(aux, sizeof(aux), "%s (REG) Size: %ld bytes, Inode: %lu, Last modified: %s", buffer->d_name, file.st_size, file.st_ino, ctime(&file.st_mtime));
            write(fd, aux, strlen(aux));
        }
        if (S_ISLNK(file.st_mode))
        {
            snprintf(aux, sizeof(aux), "%s (LINK) Size: %ld bytes, Inode: %lu, Last modified: %s", buffer->d_name, file.st_size, file.st_ino, ctime(&file.st_mtime));
            write(fd, aux, strlen(aux));
        }
    }

    if (closedir(dir) == -1)
    {
        perror("Error closing directory\n");
        exit(1);
    }
}

// Function to check if the given path is a directory
int verify_directory(const char* path, struct stat* verify)
{
    if (lstat(path, verify) == -1)
    {
        perror("Error using lstat\n");
        return 1;
    }

    if (S_ISDIR(verify->st_mode))
    {
        return 0;    // is a directory
    }
    else
    {
        return 1;    // is not a directory
    }
}

// Function to check if the given path is a link
int verify_link(const char* path, struct stat* verify)
{
    if (lstat(path, verify) == -1)
    {
        perror("Error using lstat\n");
        return 1;
    }

    if (S_ISLNK(verify->st_mode))
    {
        return 0;    // is a link
    }
    else
    {
        return 1;    // is not a link
    }
}

// Function to compare the content of two snapshots
int compare_files(const char* file1, const char* file2)
{
    char buffer1[SIZE], buffer2[SIZE];
    ssize_t read1, read2;
    int fd1, fd2;

    fd1 = open(file1, O_RDONLY);
    if (fd1 == -1)
    {
        perror("Error opening file\n");
        exit(3);
    }

    fd2 = open(file2, O_RDONLY);
    if (fd2 == -1)
    {
        perror("Error opening file\n");
        close(fd1);
        exit(3);
    }

    while ((read1 = read(fd1, buffer1, SIZE)) > 0 && (read2 = read(fd2, buffer2, SIZE)) > 0)
    {
        if (read1 != read2 || memcmp(buffer1, buffer2, read1) != 0)
        {
            close(fd1);
            close(fd2);
            return 0;
        }
    }

    close(fd1);
    close(fd2);
    return 1;
}

// Function to overwrite the old snapshot with the content of the new snapshot if differences exist
void update_snapshot(const char* old_snapshot, const char* new_snapshot)
{
    int old_fd, new_fd;

    old_fd = open(old_snapshot, O_WRONLY | O_TRUNC);
    if (old_fd == -1)
    {
        perror("Error opening old snapshot\n");
        exit(3);
    }

    new_fd = open(new_snapshot, O_RDONLY);
    if (new_fd == -1)
    {
        perror("Error opening new snapshot\n");
        close(old_fd);
        exit(3);
    }

    char buffer[SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(new_fd, buffer, SIZE)) > 0)
    {
        if (write(old_fd, buffer, bytes_read) != bytes_read)
        {
            perror("Error writing to snapshot\n");
            close(old_fd);
            close(new_fd);
            exit(3);
        }
    }

    close(old_fd);
    close(new_fd);
}

// Function to add the inode to an array
void add_inode(int* array, int elem, int* size)
{
    int index = 0;
    while (index < *size && array[index] < elem)
    {
        index++;
    }

    for (int i = *size; i > index; i--)
    {
        array[i] = array[i - 1];
    }

    array[index] = elem;
    (*size)++;
}

// Function to check if the inode exists in the array
int search_inode(int* array, int elem, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (array[i] == elem)
        {
            return 1;
        }

        if (array[i] > elem)
        {
            return 0;
        }
    }
    return 0;
}

// Function to extract the output and quarantine directories
void extract_directories(int argc, char** argv, char* output_directory, char* isolated_directory, int* output_index, int* isolated_index)
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-o") == 0)
        {
            *output_index = i + 1;
        }
        if (strcmp(argv[i], "-x") == 0)
        {
            *isolated_index = i + 1;
        }
    }

    if (*output_index == -1 || *isolated_index == -1)
    {
        perror("Missing arguments -o or -x\n");
        exit(0);
    }

    strcpy(output_directory, argv[*output_index]);
    strcpy(isolated_directory, argv[*isolated_index]);
}

// Function to process the content of the directory and its snapshot, performing overwrite if differences exist
// and creating a snapshot if not present
void process_directory(char* directory, char* output_directory, char* isolated_directory, int inode, int* array, int* size)
{
    char snapshot_path[PATH_MAX];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/snapshot_%d.txt", output_directory, inode);

    struct stat verify;
    if (lstat(snapshot_path, &verify) == 0)
    {
        char new_snapshot_path[PATH_MAX];
        snprintf(new_snapshot_path, sizeof(new_snapshot_path), "%s/new_snapshot_%d.txt", output_directory, inode);

        int new_snapshot_fd = open(new_snapshot_path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (new_snapshot_fd == -1)
        {
            perror("Error creating snapshot\n");
            exit(3);
        }

        generate_snapshot(directory, new_snapshot_fd, isolated_directory);
        close(new_snapshot_fd);

        if (compare_files(snapshot_path, new_snapshot_path) == 0)
        {
            update_snapshot(snapshot_path, new_snapshot_path);
            unlink(new_snapshot_path);
        }
        else
        {
            unlink(new_snapshot_path);
        }
    }
    else
    {
        int snapshot_fd = open(snapshot_path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
        if (snapshot_fd == -1)
        {
            perror("Error creating snapshot\n");
            exit(3);
        }

        generate_snapshot(directory, snapshot_fd, isolated_directory);
        close(snapshot_fd);
    }
}

// Main function to process the files provided as arguments, as well as generating the snapshot,
// recursively traversing the files and isolating those that are dangerous
int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        perror("Usage: program_name -o OUTPUT_DIRECTORY -x ISOLATED_DIRECTORY directory1 directory2 ...\n");
        exit(1);
    }

    char output_directory[PATH_MAX], isolated_directory[PATH_MAX];
    int output_index = -1, isolated_index = -1;

    extract_directories(argc, argv, output_directory, isolated_directory, &output_index, &isolated_index);

    struct stat verify;
    int inode;
    int array[SIZE];
    int size = 0;

    for (int i = output_index + 1; i < isolated_index - 1; i++)
    {
        if (verify_directory(argv[i], &verify) == 0)
        {
            inode = verify.st_ino;
            if (!search_inode(array, inode, size))
            {
                add_inode(array, inode, &size);
                process_directory(argv[i], output_directory, isolated_directory, inode, array, &size);
            }
        }
        else
        {
            perror("Provided path is not a directory\n");
        }
    }

    printf("Total dangerous files isolated: %d\n", count_file);
    return 0;
}
