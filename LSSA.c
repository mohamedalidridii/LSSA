#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/evp.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MAX_WATCHES 1024
#define BACKUP_DIR ".backups"
#define DEBOUNCE_SECONDS 2
#define GIT_INDEX_PATH ".git/index"
#define GIT_HEAD_PATH ".git/HEAD"

// Structure to track watch descriptors and paths
typedef struct {
    int wd;
    char path[PATH_MAX];
} WatchEntry;

// Structure to track last backup time for debouncing
typedef struct {
    char filepath[PATH_MAX];
    time_t last_backup;
} DebounceEntry;

// Global variables
static int inotify_fd = -1;
static WatchEntry watches[MAX_WATCHES];
static int watch_count = 0;
static DebounceEntry debounce_table[MAX_WATCHES];
static int debounce_count = 0;
static int git_index_wd = -1;  // Watch descriptor for .git/index
static int git_head_wd = -1;   // Watch descriptor for .git/HEAD

// Conflict tracking
typedef struct {
    char filepath[PATH_MAX];
    int warned;
} ConflictEntry;

static ConflictEntry conflict_files[MAX_WATCHES];
static int conflict_count = 0;

// Activity tracking for heatmap
typedef struct {
    char filepath[PATH_MAX];
    int change_count;
    time_t first_seen;
    time_t last_modified;
} ActivityEntry;

static ActivityEntry activity_log[MAX_WATCHES];
static int activity_count = 0;

// Allowed extensions to backup
static const char *allowed_extensions[] = {
    ".c", ".h", ".cpp", ".hpp", ".py", ".js", ".java",
    ".rs", ".go", ".sh", ".txt", ".md", ".json", ".xml",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", NULL
};

// Forward declarations
void save_activity_log();
void load_activity_log();
void display_heatmap();

// Cleanup handler
void cleanup_handler(int signum) {
    printf("\nCleaning up and exiting...\n");
    
    // Save activity log before exit
    save_activity_log();
    
    if (inotify_fd >= 0) {
        for (int i = 0; i < watch_count; i++) {
            inotify_rm_watch(inotify_fd, watches[i].wd);
        }
        close(inotify_fd);
    }
    exit(0);
}

// Check if file extension is allowed
int is_allowed_extension(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    
    for (int i = 0; allowed_extensions[i] != NULL; i++) {
        if (strcmp(dot, allowed_extensions[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Check if path should be ignored
int should_ignore(const char *name) {
    // Ignore our backup files
    if (strstr(name, ".bak_") != NULL) return 1;
    if (strstr(name, BACKUP_DIR) != NULL) return 1;
    
    // Ignore git directory
    if (strstr(name, ".git") != NULL) return 1;
    
    // Ignore compiled/binary files
    const char *ignore_extensions[] = {".o", ".so", ".a", ".pyc", ".class", NULL};
    const char *dot = strrchr(name, '.');
    if (dot) {
        for (int i = 0; ignore_extensions[i] != NULL; i++) {
            if (strcmp(dot, ignore_extensions[i]) == 0) return 1;
        }
    }
    
    return 0;
}

// Create backup directory structure
int ensure_backup_dir(const char *filepath, char *backup_path, size_t backup_path_size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_dir[64];
    
    strftime(date_dir, sizeof(date_dir), "%Y-%m-%d", tm_info);
    
    // Create .backups directory
    mkdir(BACKUP_DIR, 0755);
    
    // Create date subdirectory
    char date_path[PATH_MAX];
    snprintf(date_path, sizeof(date_path), "%s/%s", BACKUP_DIR, date_dir);
    mkdir(date_path, 0755);
    
    // Create backup filename with timestamp
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H-%M-%S", tm_info);
    
    snprintf(backup_path, backup_path_size, "%s/%s_%s", 
             date_path, timestamp, filepath);
    
    return 0;
}

// Compute SHA256 hash of file
int compute_file_hash(const char *filepath, unsigned char *hash) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(f);
        return -1;
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(f);
        return -1;
    }
    
    unsigned char buffer[8192];
    size_t bytes;
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(f);
            return -1;
        }
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(f);
        return -1;
    }
    
    EVP_MD_CTX_free(mdctx);
    fclose(f);
    return 0;
}

// Check if file content has changed using hash
int file_has_changed(const char *filepath) {
    unsigned char current_hash[EVP_MAX_MD_SIZE];
    
    if (compute_file_hash(filepath, current_hash) != 0) {
        return 1; // Assume changed if we can't read
    }
    
    // Try to find most recent backup
    char date_dir[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(date_dir, sizeof(date_dir), "%Y-%m-%d", tm_info);
    
    char search_path[PATH_MAX];
    snprintf(search_path, sizeof(search_path), "%s/%s", BACKUP_DIR, date_dir);
    
    DIR *dir = opendir(search_path);
    if (!dir) return 1; // No backups yet
    
    // Find most recent backup file
    struct dirent *entry;
    char most_recent[PATH_MAX] = "";
    time_t most_recent_time = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, filepath) != NULL) {
            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", search_path, entry->d_name);
            
            struct stat st;
            if (stat(full_path, &st) == 0) {
                if (st.st_mtime > most_recent_time) {
                    most_recent_time = st.st_mtime;
                    strncpy(most_recent, full_path, sizeof(most_recent) - 1);
                }
            }
        }
    }
    closedir(dir);
    
    if (most_recent[0] == '\0') return 1; // No backup found
    
    // Compare hashes
    unsigned char backup_hash[EVP_MAX_MD_SIZE];
    if (compute_file_hash(most_recent, backup_hash) != 0) {
        return 1;
    }
    
    return memcmp(current_hash, backup_hash, 32) != 0; // SHA256 is 32 bytes
}

// Check debounce - return 1 if should backup, 0 if too soon
int check_debounce(const char *filepath) {
    time_t now = time(NULL);
    
    for (int i = 0; i < debounce_count; i++) {
        if (strcmp(debounce_table[i].filepath, filepath) == 0) {
            if (now - debounce_table[i].last_backup < DEBOUNCE_SECONDS) {
                return 0; // Too soon
            }
            debounce_table[i].last_backup = now;
            return 1;
        }
    }
    
    // Not in table, add it
    if (debounce_count < MAX_WATCHES) {
        strncpy(debounce_table[debounce_count].filepath, filepath, PATH_MAX - 1);
        debounce_table[debounce_count].last_backup = now;
        debounce_count++;
    }
    
    return 1;
}

// Get list of files from last commit
void get_committed_files(char files[][PATH_MAX], int *count, int max_files) {
    *count = 0;
    // Get files from the last commit (HEAD)
    FILE *fp = popen("git diff-tree --no-commit-id --name-only -r HEAD 2>/dev/null", "r");
    if (!fp) return;
    
    char line[PATH_MAX];
    while (fgets(line, sizeof(line), fp) && *count < max_files) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0) {
            strncpy(files[*count], line, PATH_MAX - 1);
            (*count)++;
        }
    }
    pclose(fp);
}

// Delete all backups for a specific file
void delete_backups_for_file(const char *filename) {
    DIR *backup_root = opendir(BACKUP_DIR);
    if (!backup_root) return;
    
    struct dirent *date_entry;
    int deleted_count = 0;
    
    // Iterate through date directories
    while ((date_entry = readdir(backup_root)) != NULL) {
        if (date_entry->d_name[0] == '.') continue;
        
        char date_path[PATH_MAX];
        snprintf(date_path, sizeof(date_path), "%s/%s", BACKUP_DIR, date_entry->d_name);
        
        DIR *date_dir = opendir(date_path);
        if (!date_dir) continue;
        
        struct dirent *file_entry;
        while ((file_entry = readdir(date_dir)) != NULL) {
            // Check if this backup is for our file
            if (strstr(file_entry->d_name, filename) != NULL) {
                char backup_file[PATH_MAX];
                snprintf(backup_file, sizeof(backup_file), "%s/%s", 
                         date_path, file_entry->d_name);
                
                if (unlink(backup_file) == 0) {
                    deleted_count++;
                }
            }
        }
        closedir(date_dir);
    }
    closedir(backup_root);
    
    if (deleted_count > 0) {
        printf("Deleted %d backup(s) for %s (committed to git)\n", 
               deleted_count, filename);
    }
}

// Handle git commit - cleanup backups for committed files
void handle_git_commit() {
    // Small delay to ensure commit is complete
    sleep(1);
    
    printf("\nGit commit detected! Cleaning up backups...\n");
    
    char committed_files[256][PATH_MAX];
    int file_count = 0;
    
    get_committed_files(committed_files, &file_count, 256);
    
    if (file_count == 0) {
        printf("No committed files found.\n");
        return;
    }
    
    for (int i = 0; i < file_count; i++) {
        delete_backups_for_file(committed_files[i]);
    }
    
    printf("Backup cleanup complete!\n\n");
}

// Setup git hooks for automatic cleanup
void setup_git_hooks() {
    const char *hook_path = ".git/hooks/post-commit";
    
    FILE *hook = fopen(hook_path, "w");
    if (!hook) {
        fprintf(stderr, "Warning: Could not create git hook\n");
        return;
    }
    
    fprintf(hook, "#!/bin/sh\n");
    fprintf(hook, "# Auto-generated by LSSA backup system\n");
    fprintf(hook, "# Delete backups for committed files\n\n");
    fprintf(hook, "# Get list of committed files\n");
    fprintf(hook, "git diff-tree --no-commit-id --name-only -r HEAD | while read file; do\n");
    fprintf(hook, "  # Delete all backups for this file\n");
    fprintf(hook, "  find .backups -type f -name \"*_${file}\" -delete 2>/dev/null\n");
    fprintf(hook, "  echo \"Cleaned backups for: $file\"\n");
    fprintf(hook, "done\n");
    
    fclose(hook);
    
    // Make it executable
    chmod(hook_path, 0755);
    
    printf("Git post-commit hook installed\n");
}

// Get current git branch
void get_current_branch(char *branch, size_t size) {
    FILE *fp = popen("git branch --show-current 2>/dev/null", "r");
    if (!fp) {
        strncpy(branch, "unknown", size);
        return;
    }
    
    if (fgets(branch, size, fp)) {
        branch[strcspn(branch, "\n")] = 0;
    } else {
        strncpy(branch, "unknown", size);
    }
    pclose(fp);
}

// Check if file has different content in another branch
int check_file_differs_in_branch(const char *filepath, const char *target_branch) {
    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), 
             "git diff --quiet HEAD %s -- %s 2>/dev/null", 
             target_branch, filepath);
    
    int result = system(cmd);
    // Returns 0 if no diff (same), 1 if different, >1 if error
    return WEXITSTATUS(result) == 1;
}

// Get list of branches that have different versions of a file
void get_divergent_branches(const char *filepath, char branches[][64], int *count, int max_branches) {
    *count = 0;
    
    char current_branch[64];
    get_current_branch(current_branch, sizeof(current_branch));
    
    FILE *fp = popen("git branch 2>/dev/null", "r");
    if (!fp) return;
    
    char line[256];
    while (fgets(line, sizeof(line), fp) && *count < max_branches) {
        // Remove '* ' prefix and newline
        char *branch_name = line;
        if (line[0] == '*' && line[1] == ' ') {
            branch_name = line + 2;
        }
        branch_name[strcspn(branch_name, "\n")] = 0;
        
        // Skip current branch and empty lines
        if (strlen(branch_name) == 0 || strcmp(branch_name, current_branch) == 0) {
            continue;
        }
        
        // Check if file differs in this branch
        if (check_file_differs_in_branch(filepath, branch_name)) {
            strncpy(branches[*count], branch_name, 63);
            branches[*count][63] = '\0';
            (*count)++;
        }
    }
    pclose(fp);
}

// Check if file is already marked as conflicted
int is_conflict_warned(const char *filepath) {
    for (int i = 0; i < conflict_count; i++) {
        if (strcmp(conflict_files[i].filepath, filepath) == 0) {
            return conflict_files[i].warned;
        }
    }
    return 0;
}

// Mark file as warned
void mark_conflict_warned(const char *filepath) {
    for (int i = 0; i < conflict_count; i++) {
        if (strcmp(conflict_files[i].filepath, filepath) == 0) {
            conflict_files[i].warned = 1;
            return;
        }
    }
    
    if (conflict_count < MAX_WATCHES) {
        strncpy(conflict_files[conflict_count].filepath, filepath, PATH_MAX - 1);
        conflict_files[conflict_count].warned = 1;
        conflict_count++;
    }
}

// Scan for potential merge conflicts
void scan_for_potential_conflicts() {
    conflict_count = 0; // Reset
    
    char current_branch[64];
    get_current_branch(current_branch, sizeof(current_branch));
    
    if (strcmp(current_branch, "unknown") == 0) {
        return; // Not in a git repo or detached HEAD
    }
    
    // Get list of modified files
    FILE *fp = popen("git ls-files -m 2>/dev/null", "r");
    if (!fp) return;
    
    char filepath[PATH_MAX];
    while (fgets(filepath, sizeof(filepath), fp)) {
        filepath[strcspn(filepath, "\n")] = 0;
        
        char divergent_branches[32][64];
        int branch_count = 0;
        
        get_divergent_branches(filepath, divergent_branches, &branch_count, 32);
        
        if (branch_count > 0 && conflict_count < MAX_WATCHES) {
            strncpy(conflict_files[conflict_count].filepath, filepath, PATH_MAX - 1);
            conflict_files[conflict_count].warned = 0;
            conflict_count++;
        }
    }
    pclose(fp);
}

// Warn about potential conflicts before editing
void warn_potential_conflict(const char *filepath) {
    if (is_conflict_warned(filepath)) {
        return; // Already warned
    }
    
    char divergent_branches[32][64];
    int branch_count = 0;
    
    get_divergent_branches(filepath, divergent_branches, &branch_count, 32);
    
    if (branch_count > 0) {
        printf("\nWARNING: POTENTIAL MERGE CONFLICT\n");
        printf("========================================\n");
        printf("File: %s\n", filepath);
        printf("This file has different versions in:\n");
        
        for (int i = 0; i < branch_count && i < 5; i++) {
            printf("  - %s\n", divergent_branches[i]);
        }
        
        if (branch_count > 5) {
            printf("  ... and %d more branch(es)\n", branch_count - 5);
        }
        
        printf("\nEditing this file may cause conflicts when merging!\n");
        printf("Consider: git pull/merge before continuing\n");
        printf("========================================\n\n");
        
        mark_conflict_warned(filepath);
    }
}

// Handle branch changes
void handle_branch_change() {
    printf("\nBranch change detected! Rescanning for conflicts...\n");
    scan_for_potential_conflicts();
    
    if (conflict_count > 0) {
        printf("WARNING: Found %d file(s) with potential conflicts:\n", conflict_count);
        for (int i = 0; i < conflict_count && i < 10; i++) {
            printf("  - %s\n", conflict_files[i].filepath);
        }
        if (conflict_count > 10) {
            printf("  ... and %d more\n", conflict_count - 10);
        }
    } else {
        printf("No potential conflicts detected\n");
    }
    printf("\n");
}

// Track file activity
void track_file_activity(const char *filepath) {
    time_t now = time(NULL);
    
    // Check if file already in activity log
    for (int i = 0; i < activity_count; i++) {
        if (strcmp(activity_log[i].filepath, filepath) == 0) {
            activity_log[i].change_count++;
            activity_log[i].last_modified = now;
            return;
        }
    }
    
    // Add new entry
    if (activity_count < MAX_WATCHES) {
        strncpy(activity_log[activity_count].filepath, filepath, PATH_MAX - 1);
        activity_log[activity_count].change_count = 1;
        activity_log[activity_count].first_seen = now;
        activity_log[activity_count].last_modified = now;
        activity_count++;
    }
}

// Compare function for sorting by change count
int compare_activity(const void *a, const void *b) {
    ActivityEntry *ea = (ActivityEntry *)a;
    ActivityEntry *eb = (ActivityEntry *)b;
    return eb->change_count - ea->change_count; // Descending order
}

// Generate heat bar for visualization
void generate_heat_bar(int count, int max_count, char *bar, size_t bar_size) {
    const char *blocks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    int bar_length = 10;
    int filled = (count * bar_length) / (max_count > 0 ? max_count : 1);
    
    bar[0] = '\0';
    for (int i = 0; i < bar_length; i++) {
        if (i < filled) {
            strncat(bar, blocks[7], bar_size - strlen(bar) - 1); // Full block
        } else {
            strncat(bar, blocks[0], bar_size - strlen(bar) - 1); // Empty block
        }
    }
}

// Get heat level label
const char* get_heat_label(int count, int max_count) {
    float ratio = (float)count / (max_count > 0 ? max_count : 1);
    
    if (ratio > 0.7) return "HOT";
    if (ratio > 0.4) return "WARM";
    if (ratio > 0.1) return "COOL";
    return "COLD";
}

// Calculate time difference in human-readable format
void format_time_ago(time_t timestamp, char *buffer, size_t size) {
    time_t now = time(NULL);
    int diff = (int)difftime(now, timestamp);
    
    if (diff < 60) {
        snprintf(buffer, size, "%ds ago", diff);
    } else if (diff < 3600) {
        snprintf(buffer, size, "%dm ago", diff / 60);
    } else if (diff < 86400) {
        snprintf(buffer, size, "%dh ago", diff / 3600);
    } else {
        snprintf(buffer, size, "%dd ago", diff / 86400);
    }
}

// Display file activity heatmap
void display_heatmap() {
    if (activity_count == 0) {
        printf("\nNo activity recorded yet\n\n");
        return;
    }
    
    // Sort by change count
    ActivityEntry sorted[MAX_WATCHES];
    memcpy(sorted, activity_log, sizeof(ActivityEntry) * activity_count);
    qsort(sorted, activity_count, sizeof(ActivityEntry), compare_activity);
    
    // Find max count for scaling
    int max_count = sorted[0].change_count;
    
    printf("\n");
    printf("================================================================================\n");
    printf("                          FILE ACTIVITY HEATMAP                                 \n");
    printf("================================================================================\n\n");
    
    printf("Total files tracked: %d\n", activity_count);
    printf("Most active file: %s (%d changes)\n\n", sorted[0].filepath, sorted[0].change_count);
    
    printf("--------------------------------------------------------------------------------\n");
    printf(" File                          Activity    Changes   Last Edit                 \n");
    printf("--------------------------------------------------------------------------------\n");
    
    // Display top files (up to 20)
    int display_count = activity_count < 20 ? activity_count : 20;
    
    for (int i = 0; i < display_count; i++) {
        char bar[128];
        char time_str[32];
        
        generate_heat_bar(sorted[i].change_count, max_count, bar, sizeof(bar));
        format_time_ago(sorted[i].last_modified, time_str, sizeof(time_str));
        
        // Truncate filename if too long
        char display_name[35];
        if (strlen(sorted[i].filepath) > 30) {
            snprintf(display_name, sizeof(display_name), "...%s", 
                     sorted[i].filepath + strlen(sorted[i].filepath) - 27);
        } else {
            strncpy(display_name, sorted[i].filepath, sizeof(display_name) - 1);
            display_name[34] = '\0';
        }
        
        printf(" %-30s %s  %3d      %-12s\n",
               display_name,
               bar,
               sorted[i].change_count,
               time_str);
    }
    
    printf("--------------------------------------------------------------------------------\n");
    
    if (activity_count > 20) {
        printf("  ... and %d more file(s)\n", activity_count - 20);
    }
    
    // Statistics
    printf("\nStatistics:\n");
    
    int total_changes = 0;
    for (int i = 0; i < activity_count; i++) {
        total_changes += activity_log[i].change_count;
    }
    
    printf("  - Total changes: %d\n", total_changes);
    printf("  - Average per file: %.1f\n", (float)total_changes / activity_count);
    
    // Heat levels distribution
    int hot = 0, warm = 0, cool = 0, cold = 0;
    for (int i = 0; i < activity_count; i++) {
        float ratio = (float)activity_log[i].change_count / max_count;
        if (ratio > 0.7) hot++;
        else if (ratio > 0.4) warm++;
        else if (ratio > 0.1) cool++;
        else cold++;
    }
    
    printf("\nHeat Distribution:\n");
    printf("  [HOT]   %d file(s) - >70%% activity\n", hot);
    printf("  [WARM]  %d file(s) - 40-70%% activity\n", warm);
    printf("  [COOL]  %d file(s) - 10-40%% activity\n", cool);
    printf("  [COLD]  %d file(s) - <10%% activity\n", cold);
    
    printf("\nNote: Hot files may need refactoring or better testing\n\n");
}

// Save activity log to file
void save_activity_log() {
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/activity.log", BACKUP_DIR);
    
    FILE *f = fopen(log_path, "w");
    if (!f) return;
    
    fprintf(f, "# LSSA Activity Log\n");
    fprintf(f, "# Format: filepath,change_count,first_seen,last_modified\n");
    
    for (int i = 0; i < activity_count; i++) {
        fprintf(f, "%s,%d,%ld,%ld\n",
                activity_log[i].filepath,
                activity_log[i].change_count,
                activity_log[i].first_seen,
                activity_log[i].last_modified);
    }
    
    fclose(f);
}

// Load activity log from file
void load_activity_log() {
    char log_path[PATH_MAX];
    snprintf(log_path, sizeof(log_path), "%s/activity.log", BACKUP_DIR);
    
    FILE *f = fopen(log_path, "r");
    if (!f) return;
    
    char line[PATH_MAX + 128];
    activity_count = 0;
    
    while (fgets(line, sizeof(line), f) && activity_count < MAX_WATCHES) {
        if (line[0] == '#') continue; // Skip comments
        
        char filepath[PATH_MAX];
        int change_count;
        long first_seen, last_modified;
        
        if (sscanf(line, "%[^,],%d,%ld,%ld", 
                   filepath, &change_count, &first_seen, &last_modified) == 4) {
            strncpy(activity_log[activity_count].filepath, filepath, PATH_MAX - 1);
            activity_log[activity_count].change_count = change_count;
            activity_log[activity_count].first_seen = (time_t)first_seen;
            activity_log[activity_count].last_modified = (time_t)last_modified;
            activity_count++;
        }
    }
    
    fclose(f);
    
    if (activity_count > 0) {
        printf("Loaded %d file(s) from activity log\n", activity_count);
    }
}

// Safe file copy using fork/exec (no shell injection)
int safe_copy_file(const char *src, const char *dst) {
    pid_t pid = fork();
    
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    if (pid == 0) {
        // Child process
        execl("/bin/cp", "cp", src, dst, NULL);
        perror("execl");
        exit(1);
    }
    
    // Parent process
    int status;
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    
    return -1;
}

// Backup a file
void backup_file(const char *filepath, const char *full_path) {
    // Check if should ignore
    if (should_ignore(filepath)) return;
    
    // Check allowed extensions
    if (!is_allowed_extension(filepath)) return;
    
    // ⚠️ WARN ABOUT POTENTIAL CONFLICTS BEFORE BACKING UP
    warn_potential_conflict(filepath);
    
    // Check debounce
    if (!check_debounce(full_path)) {
        return; // Too soon since last backup
    }
    
    // Check if file actually changed
    if (!file_has_changed(filepath)) {
        printf("Skipping %s (no changes)\n", filepath);
        return;
    }
    
    char backup_path[PATH_MAX];
    ensure_backup_dir(filepath, backup_path, sizeof(backup_path));
    
    if (safe_copy_file(full_path, backup_path) == 0) {
        printf("Backed up: %s -> %s\n", filepath, backup_path);
        
        // Track activity for heatmap
        track_file_activity(filepath);
    } else {
        fprintf(stderr, "Failed to backup: %s\n", filepath);
    }
}

// Add watch for a directory
int add_watch_recursive(const char *path) {
    if (watch_count >= MAX_WATCHES) {
        fprintf(stderr, "Maximum watches reached\n");
        return -1;
    }
    
    int wd = inotify_add_watch(inotify_fd, path, 
                                IN_MODIFY | IN_CREATE | IN_MOVED_TO);
    
    if (wd < 0) {
        perror("inotify_add_watch");
        return -1;
    }
    
    watches[watch_count].wd = wd;
    strncpy(watches[watch_count].path, path, PATH_MAX - 1);
    watch_count++;
    
    printf("Watching: %s\n", path);
    
    // Recursively watch subdirectories
    DIR *dir = opendir(path);
    if (!dir) return wd;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            // Skip . and .. and hidden directories
            if (entry->d_name[0] == '.') continue;
            
            char subdir[PATH_MAX];
            snprintf(subdir, sizeof(subdir), "%s/%s", path, entry->d_name);
            
            add_watch_recursive(subdir);
        }
    }
    
    closedir(dir);
    return wd;
}

// Find path for watch descriptor
const char* get_watch_path(int wd) {
    for (int i = 0; i < watch_count; i++) {
        if (watches[i].wd == wd) {
            return watches[i].path;
        }
    }
    return ".";
}

int main(int argc, char *argv[]) {
    char buffer[BUF_LEN];
    
    // Check for command-line flags FIRST (before any initialization)
    if (argc > 1) {
        if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "stats") == 0) {
            // Load activity log and display heatmap
            load_activity_log();
            display_heatmap();
            return 0;
        }
        
        if (strcmp(argv[1], "-c") == 0) {
            // Check for potential conflicts
            printf("\nChecking for potential merge conflicts...\n");
            printf("==========================================\n\n");
            
            // Check if we're in a git repository
            struct stat st;
            if (stat(".git", &st) != 0) {
                printf("ERROR: Not in a git repository!\n");
                printf("Run this command from the root of a git project.\n\n");
                return 1;
            }
            
            // Get current branch
            char current_branch[64];
            get_current_branch(current_branch, sizeof(current_branch));
            printf("Current branch: %s\n\n", current_branch);
            
            // Get all branches
            FILE *fp = popen("git branch 2>/dev/null", "r");
            if (!fp) {
                printf("ERROR: Failed to get branch list\n");
                return 1;
            }
            
            char all_branches[100][64];
            int total_branches = 0;
            char line[256];
            
            while (fgets(line, sizeof(line), fp) && total_branches < 100) {
                char *branch_name = line;
                if (line[0] == '*' && line[1] == ' ') {
                    branch_name = line + 2;
                }
                branch_name[strcspn(branch_name, "\n")] = 0;
                
                if (strlen(branch_name) > 0 && strcmp(branch_name, current_branch) != 0) {
                    strncpy(all_branches[total_branches], branch_name, 63);
                    all_branches[total_branches][63] = '\0';
                    total_branches++;
                }
            }
            pclose(fp);
            
            if (total_branches == 0) {
                printf("No other branches found.\n\n");
                return 0;
            }
            
            printf("Analyzing %d other branch(es)...\n\n", total_branches);
            
            int found_conflicts = 0;
            
            // For each branch, find conflicting files
            for (int b = 0; b < total_branches; b++) {
                char *branch = all_branches[b];
                
                // Get list of files that differ in this branch
                char cmd[512];
                snprintf(cmd, sizeof(cmd), 
                         "git diff --name-only HEAD %s 2>/dev/null", branch);
                
                FILE *diff_fp = popen(cmd, "r");
                if (!diff_fp) continue;
                
                char conflicting_files[200][PATH_MAX];
                int file_count = 0;
                
                while (fgets(line, sizeof(line), diff_fp) && file_count < 200) {
                    line[strcspn(line, "\n")] = 0;
                    if (strlen(line) > 0) {
                        strncpy(conflicting_files[file_count], line, PATH_MAX - 1);
                        file_count++;
                    }
                }
                pclose(diff_fp);
                
                if (file_count > 0) {
                    found_conflicts = 1;
                    printf("Branch: %s\n", branch);
                    printf("----------------------------------------\n");
                    printf("Files that differ: %d\n\n", file_count);
                    
                    // Show up to 20 files per branch
                    int display_count = file_count < 20 ? file_count : 20;
                    for (int i = 0; i < display_count; i++) {
                        printf("  [%d] %s\n", i + 1, conflicting_files[i]);
                    }
                    
                    if (file_count > 20) {
                        printf("  ... and %d more file(s)\n", file_count - 20);
                    }
                    
                    printf("\n");
                }
            }
            
            if (!found_conflicts) {
                printf("SUCCESS: No conflicts found!\n");
                printf("All branches are in sync with current branch.\n\n");
            } else {
                printf("\n");
                printf("Summary\n");
                printf("========================================\n");
                printf("WARNING: Files differ across branches.\n");
                printf("Editing these files may cause merge conflicts.\n");
                printf("Consider merging or rebasing before making changes.\n\n");
            }
            
            return 0;
        }
        
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("\n");
            printf("                 ___________________\n");
            printf("                /                   \\\n");
            printf("               /    L S S A  v1.0    \\\n");
            printf("              /_______________________\\\n");
            printf("              |  |  |  |  |  |  |  |  |\n");
            printf("              |  |  |  |  |  |  |  |  |\n");
            printf("              |  |  |  |  |  |  |  |  |\n");
            printf("             _|__|__|__|__|__|__|__|__|_\n");
            printf("            |___________________________|\n");
            printf("            |      by medaly.dridi      |\n");
            printf("            |___________________________|\n\n");
            printf("          Guardian of Source History\n");
            printf("     \"Like Elissa founded Carthage, we preserve your code\"\n");
            printf("================================================================\n\n");
            printf("ELISSA - Evolving Live Incremental Source Snapshot Archive\n\n");
            printf("Named after Elissa (Dido), legendary founder of Carthage,\n");
            printf("who built an enduring legacy. ELISSA preserves your code\n");
            printf("history, building an archive that protects your work.\n\n");
            printf("Usage:\n");
            printf("  lssa           Start backup system (watch mode)\n");
            printf("  lssa -s        Show file activity heatmap (stats)\n");
            printf("  lssa -c        Check for potential merge conflicts\n");
            printf("  lssa -h        Show this help message\n");
            printf("  lssa <path>    Watch specific directory\n\n");
            printf("Features:\n");
            printf("  - Automatic file backup on every modification\n");
            printf("  - Smart deduplication (skip unchanged files)\n");
            printf("  - Git integration (cleanup on commit)\n");
            printf("  - Conflict prediction across branches\n");
            printf("  - Activity tracking and heatmap visualization\n\n");
            printf("Philosophy:\n");
            printf("  Just as Elissa wisely preserved her people and founded\n");
            printf("  a great city, ELISSA guards your source code, ensuring\n");
            printf("  no work is lost and every change is preserved.\n\n");
            return 0;
        }
    }
    
    // Only NOW initialize inotify for watch mode
    // Setup signal handlers
    signal(SIGINT, cleanup_handler);
    signal(SIGTERM, cleanup_handler);
    
    // Initialize inotify
    inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("inotify_init");
        return 1;
    }
    
    // Load previous activity log
    load_activity_log();
    
    // Determine watch path
    const char *watch_path = ".";
    if (argc > 1 && argv[1][0] != '-') {
        // If argument doesn't start with '-', treat it as a path
        watch_path = argv[1];
    }
    
    if (add_watch_recursive(watch_path) < 0) {
        fprintf(stderr, "Failed to setup watches\n");
        return 1;
    }
    
    // Watch .git/index for commits
    struct stat st;
    if (stat(GIT_INDEX_PATH, &st) == 0) {
        git_index_wd = inotify_add_watch(inotify_fd, GIT_INDEX_PATH, IN_MODIFY);
        if (git_index_wd >= 0) {
            printf("Watching git index for commits\n");
        }
    }
    
    // Watch .git/HEAD for branch changes
    if (stat(GIT_HEAD_PATH, &st) == 0) {
        git_head_wd = inotify_add_watch(inotify_fd, GIT_HEAD_PATH, IN_MODIFY);
        if (git_head_wd >= 0) {
            printf("Watching git HEAD for branch changes\n");
        }
    }
    
    // Initial scan for potential conflicts
    printf("Scanning for potential merge conflicts...\n");
    scan_for_potential_conflicts();
    if (conflict_count > 0) {
        printf("WARNING: Found %d file(s) with potential conflicts\n", conflict_count);
    } else {
        printf("No potential conflicts detected\n");
    }
    
    // Setup git hooks
    setup_git_hooks();
    
    // Create .gitignore for backups if it doesn't exist
    FILE *gitignore = fopen(".gitignore", "a");
    if (gitignore) {
        // Check if .backups is already in .gitignore
        FILE *check = fopen(".gitignore", "r");
        int has_backups = 0;
        if (check) {
            char line[256];
            while (fgets(line, sizeof(line), check)) {
                if (strstr(line, ".backups")) {
                    has_backups = 1;
                    break;
                }
            }
            fclose(check);
        }
        
        if (!has_backups) {
            fprintf(gitignore, "\n# LSSA Backup System\n.backups/\n");
            printf("Added .backups/ to .gitignore\n");
        }
        fclose(gitignore);
    }
    
    printf("\n");
    printf("              ___________________\n");
    printf("             /                   \\\n");
    printf("            /     E L I S S A     \\\n");
    printf("           /_______________________\\\n");
    printf("           |  |  |  |  |  |  |  |  |\n");
    printf("           |  |  |  |  |  |  |  |  |\n");
    printf("           |  |  |  |  |  |  |  |  |\n");
    printf("          _|__|__|__|__|__|__|__|__|_\n");
    printf("         |___________________________|\n");
    printf("         |                           |\n");
    printf("         |___________________________|\n\n");
    printf("       Guardian of Source History\n");
    printf("       Now watching your code...\n");
    printf("======================================\n\n");
    printf("Backups stored in: %s/\n", BACKUP_DIR);
    printf("Debounce: %d seconds\n", DEBOUNCE_SECONDS);
    printf("Activity tracking: enabled\n");
    printf("Press Ctrl+C to stop\n");
    printf("\nTip: Run './lssa -h' for help\n\n");
    
    // Main event loop
    int event_counter = 0;
    while (1) {
        int length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            break;
        }
        
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            // Check if this is the git index being modified (commit happened)
            if (event->wd == git_index_wd && (event->mask & IN_MODIFY)) {
                handle_git_commit();
                i += EVENT_SIZE + event->len;
                continue;
            }
            
            // Check if HEAD changed (branch switch)
            if (event->wd == git_head_wd && (event->mask & IN_MODIFY)) {
                handle_branch_change();
                i += EVENT_SIZE + event->len;
                continue;
            }
            
            if (event->len) {
                const char *watch_path = get_watch_path(event->wd);
                char full_path[PATH_MAX];
                
                snprintf(full_path, sizeof(full_path), "%s/%s", 
                         watch_path, event->name);
                
                if (event->mask & IN_CREATE) {
                    // Check if it's a directory
                    struct stat st;
                    if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                        if (!should_ignore(event->name)) {
                            add_watch_recursive(full_path);
                        }
                    }
                } else if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
                    backup_file(event->name, full_path);
                }
            }
            
            i += EVENT_SIZE + event->len;
        }
        
        // Auto-save activity log every 10 events
        event_counter++;
        if (event_counter >= 10) {
            save_activity_log();
            event_counter = 0;
        }
    }
    
    cleanup_handler(0);
    return 0;
}
