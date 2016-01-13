
#pragma pack(0)
#define PLOOPCOPY_MARKER 0x4cc0ac3d
struct xfer_desc
{
	__u32   marker;
	__u32   size;
	__u64   pos;
};
#pragma pack()
