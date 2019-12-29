#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

enum SuccessEnum{
    FAILURE = 0,
    SUCCESS = 1
};

SuccessEnum scan_dirpath(char *path)    //递归扫描该目录下所有的文件和目录  
{
	char file_path[512] = {0};  
	char file[512] = {0};  
	DIR *dir = NULL;  
	struct dirent *ptr = NULL;  
	struct stat buf;
	int i=0, j=0;
	
	/****************浏览目录***************************/  
	if ((dir = opendir(path)) == NULL) 
	{
        printf("path %s open error\n",path);
		return FAILURE;  
	}

	while((ptr = readdir(dir)) != NULL) 
	{  
		if (ptr->d_name[0] != '.') 	// 不是隐藏文件
		{
			//除去根文件目录  
			strcpy(file_path, path);  
			if (path[strlen(path) - 1] != '/'){
				strcat(file_path, "/");	// file_path 后面添加一个 "/"
			}
			strcat(file_path, ptr->d_name);         //构建完整的文件名  
			assert(stat(file_path, &buf) != -1);	//断言一定有这个文件
			
			if(S_ISREG(buf.st_mode)) 					// 判断为普通文件
			{
				// 遍历 file_path ， 取得最后的文件名称存入 file
				for(i = 0; i < strlen(file_path); i++)
				{  
					if(file_path[i] == '/') 
					{  
						memset(file, 0, strlen(file));  
						j = 0;  
						continue;  
					}
					file[j++] = file_path[i];
				}
                printf("文件 %s\n",file);
			}
			else if(S_ISDIR(buf.st_mode)) 	            //判断是目录  
			{   
				scan_dirpath(file_path);       // 递归
			}  
		}
        else
        {
            if(0==strcmp(ptr->d_name,".") || 0==strcmp(ptr->d_name,".."))
                continue;
            printf("隐藏文件 %s\n",ptr->d_name);   
        }
	} 
	closedir(dir);
	return SUCCESS;  
}

int main(int argc,char *argv[])
{
    scan_dirpath(argv[1]);
    return 0;
}