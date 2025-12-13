---
layout: post
title: Исследование сетевого протокола Hytale Launcher
image: "https://hytale.com/static/images/logo.png"
category: hack
author: Me
---

> Данный материал представлен исключительно в образовательных целях в контексте исследования клиентской логики и локального сетевого взаимодействия. Все эксперименты выполнялись в изолированной среде, на собственной копии ПО, с перенаправлением всех сетевых запросов на   `127.1.0.1`. Работа велась без подключения к реальным сервисам и без взаимодействия с инфраструктурой разработчиков.

>  Модификация бинарного файла выполнялась на уровне локальных строковых констант (перенаправление URL) и использовалась исключительно для анализа механизма запуска локального HTTP-сервера лаунчером. Никаких попыток получить доступ к защищённым ресурсам, обойти механизмы авторизации или взаимодействовать с внешними серверами не предпринималось. 

> Исследование не затрагивает реальные аккаунты, пользователей или игровые данные. Любые действия, связанные с модификацией ПО и анализом сетевого трафика в отношении продакшен-сервисов, могут нарушать ToS и законодательство. Настоящий материал предназначен лишь для демонстрации подходов к техническому анализу клиентских приложений в рамках Reverse Engineering / Application Security.


# Контекст

Лаунчер был предназначен для внутренних тестов разработчиков Hytale и использовал механизм OAuth-подобной авторизации через браузер. Моя задача заключалась не в получении доступа к сервисам, а в изучении того, **как устроен сам клиент**, как он формирует запросы и как реагирует на ответы.

При этом я придерживался строгих ограничений:

- никаких запросов к оригинальным серверам,
- отсутствие распространения закрытых данных,
- изолированная среда,
- все изменения касались только перенаправления HTTP-адресов на `127.1.0.1`.

---

# Активация WebView

Для анализа сетевых запросов и внутренней логики приложения стало необходимо активировать DevTools в встроенном WebView. Приложение было написано на Go и использовало фреймворк Wails, который, в свою очередь, интегрирует компонент WebView2.

Через IDA Pro была изучена структура приложения. Как стало извствно по косвенным признакам - это Go приложение использующее библиотеку Wails (WebView2). WebView2 работает через движок EmbeddedBrowserWebView.dll, который загружается в процесс при запуске.

Для активации WebView приложение было запущено в WinBbg в режиме отладки. 

### Поиск момента инициализации WebView

Для того чтобы перехватить и активировать DevTools, приложение запускалось в WinDbg.
Первым шагом был поставлен брейкпоинт на загрузку библиотеки:
```
sxe ld:EmbeddedBrowserWebView.dll
g
```
После загрузки DLL в WinDbg стали доступны PDB-символы, что позволяет навигацию по методам C++-классов движка WebView2.

### Перехват инициализации Core-объекта WebView

Из символов библиотеки стало понятно, что реальная логика WebView находится внутри класса:

```
embedded_browser_webview::EmbeddedBrowserWebViewCore
```

Метод OnInitializeWebViewCompleted вызывается в тот момент, когда WebView полностью сформирован — завершена инициализация, IPC-каналы активны и объект готов к использованию.

Был установлен брекпоинт на EmbeddedBrowserWebViewCore::OnInitializeWebViewCompleted. 

После срабатывания брейка проверяем RCX — указатель на Core-объект:
```
r rcx
dq @rcx L10
```

Если объект содержит реальные данные (например, vtable), значит перед нами полноценный экземпляр WebViewCore, а не временный wrapper.

Пример ответа:

```
00005b90`00130150  00007ffe`1cc2e540 00007ffe`1cc2e920
00005b90`00130160  00000000`00000000 00005b90`00130170
00005b90`00130170  00000000`00000000 00000000`00000000
00005b90`00130180  00000000`00000000 00005b90`00130190
00005b90`00130190  00000000`00000000 00000000`00000000
00005b90`001301a0  00000000`00000000 00000000`00000000
00005b90`001301b0  00000000`00000000 00000000`00000000
00005b90`001301c0  00007ffe`1cc2e958 00007ffe`1cc2e968
```

### Поиск метода DevTools

При помощи команды `x EmbeddedBrowserWebView!*OpenDevToolsWindow*` мы получаем вывод методов данной библиотеки:

```
0007ffe`1cb17f50 EmbeddedBrowserWebView!embedded_browser::mojom::EmbeddedBrowser::OpenDevToolsWindow_Sym::IPCStableHash (void)
00007ffe`1cb3a020 EmbeddedBrowserWebView!embedded_browser::mojom::internal::EmbeddedBrowser_OpenDevToolsWindow_Params_Data::Validate (public: static bool __cdecl embedded_browser::mojom::internal::EmbeddedBrowser_OpenDevToolsWindow_Params_Data::Validate(void const *,class mojo::internal::ValidationContext *))
00007ffe`1c858100 EmbeddedBrowserWebView!embedded_browser_webview_current::EmbeddedBrowserWebView::OpenDevToolsWindow (public: virtual long __cdecl embedded_browser_webview_current::EmbeddedBrowserWebView::OpenDevToolsWindow(void))
00007ffe`1cb1b580 EmbeddedBrowserWebView!embedded_browser::mojom::EmbeddedBrowserProxy::OpenDevToolsWindow (public: virtual void __cdecl embedded_browser::mojom::EmbeddedBrowserProxy::OpenDevToolsWindow(void))
00007ffe`1c8c0436 EmbeddedBrowserWebView!embedded_browser_webview::EmbeddedBrowserWebViewCore::OpenDevToolsWindow (public: long __cdecl embedded_browser_webview::EmbeddedBrowserWebViewCore::OpenDevToolsWindow(void))
00007ffe`1cb3a012 EmbeddedBrowserWebView!embedded_browser::mojom::internal::EmbeddedBrowser_OpenDevToolsWindow_Params_Data::EmbeddedBrowser_OpenDevToolsWindow_Params_Data (private: __cdecl embedded_browser::mojom::internal::EmbeddedBrowser_OpenDevToolsWindow_Params_Data::EmbeddedBrowser_OpenDevToolsWindow_Params_Data(void))
00007ffe`1c909100 EmbeddedBrowserWebView!embedded_browser_webview_deprecated613::EmbeddedBrowserWebView::OpenDevToolsWindow (public: virtual long __cdecl embedded_browser_webview_deprecated613::EmbeddedBrowserWebView::OpenDevToolsWindow(void))
00007ffe`1c8e4d80 EmbeddedBrowserWebView!embedded_browser_webview_deprecated721::EmbeddedBrowserWebView::OpenDevToolsWindow (public: virtual long __cdecl embedded_browser_webview_deprecated721::EmbeddedBrowserWebView::OpenDevToolsWindow(void))
```
WinDbg показывает несколько реализаций, включая deprecated-версии и proxy-методы. Нас интересует именно та, что находится в Core, а не во wrapper’ах:

Отсюда мы видим `base address: ` 00007ffe\`1c8c0436 метода `EmbeddedBrowserWebView!embedded_browser_webview::EmbeddedBrowserWebViewCore::OpenDevToolsWindow`. Данный момент и отвечает за запуск окна DevTools.

### Вызов DevTools вручную

Теперь, когда у нас есть:

- корректный this (RCX указатель на WebViewCore)
- адрес метода DevTools (OpenDevToolsWindow)

Мы можем напрямую вызвать DevTools и продолжить выполнение командой `g`

```
r rip = 00007ffa`9a150436
g
```

# Изучение авторизации

## Первое наблюдение: авторизация через браузер

Первоначально я предполагал, что после авторизации браузер должен вернуть ссылку вида:

```
hytale://authorization_finish?code=...
```

Я использовал `URLProtocolView`, чтобы перехватывать потенциальные custom-протоколы в системе. Однако стало ясно, что лаунчер вообще не работает с кастомными URI-схемами. Никакого `hytale://…` не существует.

Это означало, что механизм авторизации построен иначе.

## Анализ redirect-URL

Я начал детально анализировать URL, который открывает браузер:

```
/oauth2/auth?client_id=hytale-launcher&state=...
```

Параметр `state` выглядел как Base64-строка. После декодирования я увидел примерно такую структуру:

```python
{
    "state": "MXRQEYO3DNS5MPS2F4QCAS6KKS",
    "port": "21227"
}
```

Это стало ключевым моментом. Оказалось, что лаунчер:

Каждый запуск поднимает свой локальный HTTP-сервер

Сервер слушает случайный порт, указанный в state

После авторизации браузер должен сделать redirect именно туда

То есть браузер после авторизации должен отправить запрос назад в лаунчер, используя временный порт.

## Реконструкция авторизационного потока

Декодировав state, я понял, что единственное, чего ждёт клиент — это:

- `code` (любое число)
- `state` (тот же самый, что он сгенерировал)
- `запрос` на 127.0.0.1 и порт, указанный в state

Реализация перенаправления в тестовом сервере выглядела так:

```python
decoded = base64.urlsafe_b64decode(state_str).decode("utf-8")
dict_state = ast.literal_eval(decoded)

url = f"http://127.0.0.1:{dict_state['port']}/?code=11&state={dict_state['state']}"
requests.get(url, timeout=1)
```

# Перенаправление запросов лаунчера

Чтобы локальный сервер принимал запросы, я заменил оригинальные домены в бинарном файле лаунчера на:

```
http://127.1.0.1:8080/
```

![https://i.imgur.com/IfuqXK3.png](https://i.imgur.com/IfuqXK3.png)

Этот шаг позволил лаунчеру корректно завершить процесс авторизации и перейти к запросу токенов.

С этого момента весь трафик шёл в мой сервер, а не во внешние ресурсы.

# Реализация сервера на низком уровне

Сервер был реализован напрямую через socket, чтобы максимально повторить структуру «сырых» HTTP-ответов. В частности, лаунчер оказался чувствительным к:

- отсутствию лишних CRLF,
- правильному Content-Length,
- своевременному закрытию соединений.

Фрагмент обработки запроса /token:

```python
if "/token" in parsed.path:
    token_json = (
        '{'
        '"access_token": "eyJhbGciOiJIUzI1...fake...",'
        '"token_type": "Bearer",'
        '"expires_in": 3600,'
        '"refresh_token": "fake_refresh_token"'
        '}'
    )

    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(token_json)}\r\n"
        "Connection: close\r\n"
        "\r\n" +
        token_json
    )

    connection.sendall(response.encode())
```

После этого лаунчер продолжал загрузку и отправлял следующий запрос на получение профиля.

# Итоги

В результате исследования был создан полностью совместимый локальный mock-server, который:

- корректно обрабатывает все запросы лаунчера Hytale;

- полностью повторяет схему авторизации через браузер;

- правильно отправляет redirect на временный порт лаунчера;

- предоставляет тестовые ответы для /token и /get-launcher-data;

- позволяет изучать интерфейс и поведение лаунчера без подключения к внешним сервисам.

Проект выполнялся строго в исследовательских целях, без попыток получить доступ к реальной инфраструктуре разработчиков Hytale.

---

Если вы HR или техлид — буду рад обсудить, как применить этот опыт в вашем продукте.
Связаться: https://t.me/Russia_gos_duma

Безопасность прежде всего! 🛡️
