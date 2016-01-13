
#define SENDFILE_TEST_PORT 1813

#pragma pack(0)
struct command {
	unsigned char id;
	unsigned int data;
};
#pragma pack()
#define CMD_SIZE	1
