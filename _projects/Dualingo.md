---
layout: project
title: Dualingo Roleplay Modification
image: 'https://i.imgur.com/tC64YpL.png'
tags:
  - hack
  - android
category: modification
date: 2025-01-01
---

Dualingo — это популярное приложение для изучения языков, но функция Roleplay доступна только для ограниченного числа курсов и языков. Это ограничение делает невозможным использование этой мощной функции для большинства пользователей. Я решил изменить это, создав модификацию, которая снимает эти ограничения.

Для реализации модификации я использовал реверс-инжиниринг APK-файла Dualingo с помощью инструментов, таких как apktool и jadx. Затем я вручную редактировал smali-код, чтобы обойти проверки на доступность Roleplay для определённых курсов. После этого я пересобирал APK и тестировал его на различных устройствах, чтобы убедиться в корректности работы модификации.

### Особенности модификации:

- **Универсальная поддержка:** Работает на всех курсах и языках.
- **Сохранение прогресса:** Все ваши достижения сохраняются.
- **Лёгкая установка:** Модификация совместима с последними версиями Dualingo.


![Скриншот Roleplay](https://i.imgur.com/WE7770I.jpeg)
![Скриншот Roleplay](https://i.imgur.com/cceJdlA.jpeg)
_Пример использования Roleplay на курсе, где функция недоступна по умолчанию._

## Сложности и решение

Для реализации обхода этих проверок я использовал метод дизассемблирования APK с помощью apktool и ручного анализа smali. 
После того как я определил ключевые места, где происходила валидация через фичу `ROLEPLAY_FOR_INTERMEDIATE_LEARNERS`, 
я заменил соответствующие вызовы на константные значения, возвращающие true, либо напрямую подменил логику сравнения — например, 
с помощью возврата нужных `enum`'ов или подстановки фиктивных условий `(const/4 v0, 0x1)`. Также была отключена логика в PlusViewModel.n, возвращающая статус отображения фич — путём замены результата метода.

Ссылка для ознакомления: [Dualingo Roleplay Mod](https://drive.google.com/file/d/1R9peok-Bhnq1vZVu5ULqPJnKfSME1ohS/view?usp=sharing)
