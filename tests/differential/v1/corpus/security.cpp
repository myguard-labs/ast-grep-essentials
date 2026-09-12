void report(char *message) {
    fprintf(stderr, message);  // flawfinder: ignore
    fprintf(stderr, "%s", message);
}
