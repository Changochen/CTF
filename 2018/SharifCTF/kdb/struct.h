#pragma once

struct Chunk{
    char name[32];
    unsigned long size;
};

struct Manage{
    struct Chunk2* next;
    struct Chunk2* prev;
};


struct Chunk2{
    char name[32];
    char* buffer;
    unsigned long size;
    struct Manage man;
};
