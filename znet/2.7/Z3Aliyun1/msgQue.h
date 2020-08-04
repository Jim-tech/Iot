#ifndef __MSG_QUE__
#define __MSG_QUE__

#include <kernel/include/os.h>

#define MSG_BUFFER_UNIT_SIZE     126
#define MSG_BUFFER_MAX_NUM       64

typedef struct appMsgHdr
{
	uint8_t    msgCmd;   //valid range [0-254]. Use 255 to indicate it's free.
	uint8_t    dataLen;
	uint8_t    data[MSG_BUFFER_UNIT_SIZE];
}AppMsgHdr;

extern AppMsgHdr g_appMsgBuffer[MSG_BUFFER_MAX_NUM];

void msgq_InitBuffer();
AppMsgHdr *msgq_AllocBuffer();
void msgq_FreeBuffer(AppMsgHdr *pBuffer);

int msgq_CreateMsgQ(OS_Q *pQue, char *pName, uint8_t size);
AppMsgHdr *msgq_DeQueue(OS_Q *pQue);
void msgq_EnQueue(OS_Q *pQue, AppMsgHdr *pMsg);

#endif // __MSG_QUE__
