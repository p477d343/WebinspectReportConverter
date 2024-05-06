import time
import os
from os import path
#path = r'C:\Users\USER\Desktop\2023scan2th'
#path = input("請輸入資料夾路徑：")
path = os.getcwd()


for (root, dirs, file) in os.walk(path):
    for f in file:
        if '.pdf' in f:
            if " " in f:
                os.rename(root+"//"+f, root+"//"+f.replace(" ","_"))
                f = f.replace(" ","_")
            if ")" in f:
                os.rename(root+"//"+f, root+"//"+f.replace(")",""))
                f = f.replace(")","")
            if "(" in f:
                os.rename(root+"//"+f, root+"//"+f.replace("(",""))
                f = f.replace("(","")
            fullname = str(root)+'/'+str(f)
            fullname = fullname.replace(" ","_").replace("(","").replace(")","")

            textname = fullname[:-4] + ".txt"
            textname = textname.replace(" ","_").replace("(","").replace(")","")

            os.system("pdftotext -nopgbrk " + fullname + " " + textname)            

                
            os.system('python split_webinspect_web_application_assessment_report.py ' + textname + " " + fullname[:-4])
