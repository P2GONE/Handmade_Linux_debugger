# Handmade_Linux_debugger
## Build
```
cd BreadcrumbsHandmade_Linux_debugger
make
```
### Running
Turn off the protection for convenience in the debugger

```
gcc -g -O0 -fno-stack-protector -no-pie -Wl,-z,norelro -z execstack -fno-omit-frame-pointer -fno-asynchronous-unwind-tables -o target_file target_file.c
```
./my_debugger ./target_file

