#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char *argv[])
{
    //declaring variable
    FILE *fp,*fr;
    int i;
    int counter,flag;
    int next;
    char reading_file[100];
    char writing_file[100];
    unsigned int packet_head[4];
    unsigned int time_second;
    unsigned int time_usecond;
    unsigned int length;
    unsigned int interval;
    char str[10];

    //open the file
    strcpy(reading_file,"");
    strcat(reading_file,"./");
    strcat(reading_file,argv[1]);
    strcat(reading_file,".pcap");
    fp = fopen(reading_file,"rb");
    strcpy(writing_file,"");
    strcat(writing_file,"./");
    strcat(writing_file,argv[1]);
    strcat(writing_file,"_processing_time.dat");
    printf("%s\n",writing_file);
    fr = fopen(writing_file,"w");
    if(fp==NULL || fr == NULL)
    {
        printf("can not open the file!\n");
        exit(0);
    }

    //read the file
    fseek(fp,24,SEEK_CUR);
    if(fread(&packet_head,sizeof(unsigned int),4,fp)==0)
    {
        printf("error!\n");
    }
    time_second = packet_head[0];
    time_usecond = packet_head[1];
    length = packet_head[2];
    fseek(fp,length,SEEK_CUR);
    interval = 0;
    counter = 0;
    flag = 0;
    //next = 1;
    while(1)
    {
        if(fread(&packet_head,4,4,fp)==0)
        {
            printf("error!\n");
            flag = 1;
        }
        // 138 is the length of OFPT_MULTIPART_REQUEST
        if(packet_head[2] == 138 || flag == 1)
        {
            printf("%u\n",interval);
            sprintf(str,"%u\n",interval);
            fputs(str,fr);
            interval = 0;
            time_second = packet_head[0];
            time_usecond = packet_head[1];
            length = packet_head[2];
            counter = counter + 1;
            //next = 1;
            printf("number %d\n", counter);
        }
        else 
        {
            /*if(next == 1)
            {
                interval = interval + (packet_head[0] - time_second) * 1000000 + (packet_head[1] - time_usecond);
                next = 0;
            }*/
            interval = interval + (packet_head[0] - time_second) * 1000000 + (packet_head[1] - time_usecond);
            time_second = packet_head[0];
            time_usecond = packet_head[1];
            length = packet_head[2];
        }
        printf("length is %u\n",length);
        if(flag)
        {
            break;
        }
        else
        {
            fseek(fp,length,SEEK_CUR);
        }
        //printf("%u,%u,%u,%u\n",packet_head[0],packet_head[1],packet_head[2],packet_head[3]);
    }
    fclose(fp);
    fclose(fr);
    return 0;
}

