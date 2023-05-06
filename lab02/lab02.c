#include <stdio.h>
#include <dirent.h>
#include <string.h>

char* find_str;

unsigned long long getfile(char* path)
{

  char path_ch[512];
  DIR			*dp;
  struct dirent	*dirp;

  if ((dp = opendir(path)) == NULL)
      fprintf(stderr, "can't open %s", path);
  while ((dirp = readdir(dp)) != NULL)
  {
      if(strcmp(dirp->d_name, "..")==0 || strcmp(dirp->d_name, ".")==0) 
          continue;
          
      if(dirp->d_type == DT_REG)    
      {
          //fprintf(stderr, "file: %s\n", dirp->d_name);    
          sprintf(path_ch, "%s/%s", path, dirp->d_name);
          
          FILE* fp = fopen(path_ch, "r");
          char str[512];
          if (fp == NULL)
          {
		//fprintf(stderr, "Error: Failed to open file %s\n", path_ch);
		continue;              
          }
          while(fgets(str, sizeof(str), fp) != NULL)
          {
		if(strstr(str, find_str) != NULL)  //found find_str in str
		{
		    fprintf(stderr, "%s\n\n\n\n\n\n", path_ch);  
		    printf("%s\n", path_ch); 
		}    
          }
          fclose(fp);
      }
          
          
      if(dirp->d_type == DT_DIR)
      {
          //fprintf(stderr, "dir: %s\n", dirp->d_name);
          sprintf(path_ch, "%s/%s", path, dirp->d_name);
          
          getfile(path_ch);
      }
          
  }

  closedir(dp);

}


int main(int argc, char *argv[]) 
{

    
  find_str = argv[2];  
  fprintf(stderr, "%s, %s\n\n\n", argv[1], argv[2]);
  
  
  
  
  getfile(argv[1]);
  
  return 0;
}

//gcc lab02.c -o lab02 -static
//python submit.py ./lab02
