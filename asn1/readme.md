# Задание для отчета
1. Изучить этапы работы центра сертификации
2. Выбрать средства реализации, совместимые с Astra Linux
3. Изучить синтаксис ASN.1
4. Изучить структуру запроса на сертификат согласно стандарту PKCS#10 
5. Изучить структуру сертификата согласно стандарту x.509
5. Реализовать функции для декодирования и анализа содержимого запроса на сертификат
6. Реализовать функции формирования содержимого сертификата для дальнейшей подписи

# Как запустить:
```bash
source ./prep_bicr.sh
```

# Про библиотеки
Были рассмотрены библиотеки для работы с данными на основе стандарта ASN.1:
- **cryptography** - содержит готовые схемы для стандартов: X.509, PKCS и т д; не поддерживает ГОСТ алгоритмы (нужны дополнительные библиотеки)
- **pyasn1** - ASN.1-структуры описываются в коде через классы
- **python-asn1** - низкоуровневая работа с asn1; не содержит схем

Была выбрана библиотека python-asn1, из-за ее простоты и минималестичности: она декодирует ASN.1-структуры напрямую, без избыточных обёрток в виде дополнительных классов, что обеспечивает гибкость при обработке данных и исключает проблемы с кодированием данных на этапе подписи. Так же она не требует использования дополнительных библиотек для поддержки ГОСТ-алгоритмов.

# Что сделано на 07.07.25
Из запроса на сертификат (CA_Prac_2025/asn1/csr/full.p10) конструируется структура tbsCertificate, в соответствии со стандартами: [rfc5280](https://www.ietf.org/rfc/rfc5280.txt) и [rfc2986](https://www.ietf.org/rfc/rfc2986.txt). Т е необходимые ветви дерева запроса просто копирутся на нужные места в дереве сертификта (например rdnSequence: данные содержащиаеся в ней не разбираются, а просто переносятся)

Структура tbsCertificate в дальнейшем будет передана на подпись (так как произоводится прямая работа с буферами, то с этим проблем не должно возникнуть).

## Пример для просмотра в декодере онлайн
Содержимое full.p10:
```
-----BEGIN CERTIFICATE REQUEST-----
MIICTjCCAfsCAQAwggEqMSQwIgYDVQQKDBvQuNC8X9C+0YDQs9Cw0L3QuNC30LDR
htC40LgxCzAJBgNVBAYTAlJVMTwwOgYDVQQIDDMwMSDQoNC10YHQv9GD0LHQu9C4
0LrQsCDQkNC00YvQs9C10Y8gKNCQ0LTRi9Cz0LXRjykxGjAYBgNVBAcMEdC90LDR
gV/Qv9GD0L3QutGCMRMwEQYDVQQJDArQsNC00YDQtdGBMRowGAYDVQQDDBHQvtCx
0YnQtdC1X9C40LzRjzEXMBUGA1UEBAwO0YTQsNC80LjQu9C40Y8xDzANBgNVBCoM
BtC40LzRjzEjMCEGA1UECwwa0L/QvtC00YDQsNC30LTQtdC70LXQvdC40LUxGzAZ
BgNVBAwMEtC00L7Qu9C20L3QvtGB0YLRjDBmMB8GCCqFAwcBAQEBMBMGByqFAwIC
IwIGCCqFAwcBAQICA0MABEDipmKOv6y6hjbYxz7dxGdi/dzZhz/FQ/kkufKNG00w
blvFxZR9fPQVeOL0UmnYY+9wvusp6F6qYT/v2dxqxmE9oGAwXgYJKoZIhvcNAQkO
MVEwTzAOBgNVHQ8BAf8EBAMCBsAwCQYDVR0TBAIwADAdBgUqhQNkbwQUDBLQkdC4
0LrRgNC40L/RgiA1LjAwEwYDVR0gBAwwCjAIBgYqhQNkcQEwCgYIKoUDBwEBAwID
QQB3JkME/sOp6PtF/3ODP1oM3wQbz01oXy6/ShFZVEeFQiCiCbwxBFzRKbKslQ51
tbb0AuedDZOsG6uYNmbZeeSH
-----END CERTIFICATE REQUEST-----
```

Превращается в сертификат(неподписанный) res.pem:
```
-----BEGIN CERTIFICATE-----
MIIDAzCCAv+gAwIBAAIIKjHDHXNXM9kwCgYIKoUDBwEBAQEwggEqMSQwIgYDVQQK
DBvQuNC8X9C+0YDQs9Cw0L3QuNC30LDRhtC40LgxCzAJBgNVBAYTAlJVMTwwOgYD
VQQIDDMwMSDQoNC10YHQv9GD0LHQu9C40LrQsCDQkNC00YvQs9C10Y8gKNCQ0LTR
i9Cz0LXRjykxGjAYBgNVBAcMEdC90LDRgV/Qv9GD0L3QutGCMRMwEQYDVQQJDArQ
sNC00YDQtdGBMRowGAYDVQQDDBHQvtCx0YnQtdC1X9C40LzRjzEXMBUGA1UEBAwO
0YTQsNC80LjQu9C40Y8xDzANBgNVBCoMBtC40LzRjzEjMCEGA1UECwwa0L/QvtC0
0YDQsNC30LTQtdC70LXQvdC40LUxGzAZBgNVBAwMEtC00L7Qu9C20L3QvtGB0YLR
jDAeFw0yNTA2MDcwMDAwMDBaFw0yNTA2MDcwMDAwMDBaMIIBKjEkMCIGA1UECgwb
0LjQvF/QvtGA0LPQsNC90LjQt9Cw0YbQuNC4MQswCQYDVQQGEwJSVTE8MDoGA1UE
CAwzMDEg0KDQtdGB0L/Rg9Cx0LvQuNC60LAg0JDQtNGL0LPQtdGPICjQkNC00YvQ
s9C10Y8pMRowGAYDVQQHDBHQvdCw0YFf0L/Rg9C90LrRgjETMBEGA1UECQwK0LDQ
tNGA0LXRgTEaMBgGA1UEAwwR0L7QsdGJ0LXQtV/QuNC80Y8xFzAVBgNVBAQMDtGE
0LDQvNC40LvQuNGPMQ8wDQYDVQQqDAbQuNC80Y8xIzAhBgNVBAsMGtC/0L7QtNGA
0LDQt9C00LXQu9C10L3QuNC1MRswGQYDVQQMDBLQtNC+0LvQttC90L7RgdGC0Yww
ZjAfBggqhQMHAQEBATATBgcqhQMCAiMCBggqhQMHAQECAgNDAARA4qZijr+suoY2
2Mc+3cRnYv3c2Yc/xUP5JLnyjRtNMG5bxcWUfXz0FXji9FJp2GPvcL7rKeheqmE/
79ncasZhPQ==
-----END CERTIFICATE-----
```

# Вопросы
- На данном этапе в сертификат еще не была добавлена ветвь extensions, которая должна содержать: ветвь attribute из запроса на сертификат + данные о самом центре сертификации. Откуда и какие данные брать о ЦС? написать такие же как в сертификатах содаваемых вашим приложением под windows?
- Я правильна поняла, что шаблон сертификата определяет набор полей и их значения в ветви extensions дерева сертификата. Ту чась ветви, которая указывает данные о самом ЦС? Или шаблон может также задавать перечень полей для Issuer и Subject?
- В вашем приложении под windows для создания самоподписанного сертификата используется запрос на сертификат (в 'Путь к запросу' и 'Путь к сертификату УЦ' просто указываются одинаковые запросы (.p10) и в самом сертификате тогда в Issuer и Subject указываются одинаковые данные). Но на встрече с вами мы обсуждали что для создания самоподписанного сертификата на вход поступает набор полей: в таком случае мне надо будет самой сформировать rdnSequence для Issuer и Subject? Каким из этих двух способов делать?
