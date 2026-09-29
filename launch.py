#!/usr/bin/env python3
"""Локальное окружение и меню запуска. Сам по себе телефон не изменяет."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def python_environment():
    if sys.version_info < (3, 11):
        raise RuntimeError('Нужен Python 3.11 или новее: https://www.python.org/downloads/')
    if sys.platform == 'win32' and sys.maxsize <= 2**32:
        raise RuntimeError('На Windows нужен Python x64.')
    env = ROOT / '.venv'
    python = env / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
    if not env.exists():
        print('Создаю локальное окружение .venv…', flush=True)
        subprocess.run([sys.executable, '-m', 'venv', str(env)], check=True)
    if not python.is_file():
        raise RuntimeError('Папка .venv неполная или создана на другой ОС. Переименуйте её и повторите запуск.')
    probe = subprocess.run([str(python), '-c',
        'import sys; assert sys.version_info >= (3,11); '
        'assert sys.platform != "win32" or sys.maxsize > 2**32'], capture_output=True)
    if probe.returncode:
        raise RuntimeError('Python в .venv не подходит. Переименуйте папку .venv и повторите запуск.')
    dependencies = subprocess.run([str(python), '-c',
        'from importlib.metadata import version; '
        'assert version("pymobiledevice3") == "11.12.5"; '
        'from pymobiledevice3.services.afc import AfcService; '
        'from pymobiledevice3.services.installation_proxy import InstallationProxyService'], capture_output=True)
    if dependencies.returncode:
        print('Устанавливаю зависимости в .venv. Для этого нужен интернет…', flush=True)
        subprocess.run([str(python), '-m', 'pip', 'install', '--disable-pip-version-check',
                        '-r', str(ROOT / 'requirements.txt')], check=True)
    return python


def menu():
    print('\n' + '─' * 56)
    print('  CarrierSIM  ·  Vodafone HU')
    print('  Один профиль для всех SIM · привязка по IMSI')
    print('  Исследование, разработка и тесты — Vladimir B / vlw')
    print('  vlwwwwww@gmail.com')
    print('─' * 56)
    print('  1  Установить профиль\n'
          '  2  Посмотреть SIM и план установки\n'
          '  3  Проверить компьютер и файлы\n\n'
          '  4  Вернуть штатные профили (удалить IMSI-ссылки)\n'
          '  5  Восстановить после сбоя\n'
          '  6  Открыть справку\n\n'
          '  0  Выход\n')
    while True:
        choice = input('  Ваш выбор: ').strip()
        if choice == '0': return None
        if choice == '1': return []
        if choice == '2': return ['--status']
        if choice == '3': return ['--check']
        if choice == '6': return ['--help']
        if choice == '4': return ['--restore']
        if choice == '5': return ['--recover']
        print('Введите число от 0 до 6. Установка ещё не начата.')


def main():
    os.chdir(ROOT)
    python = None
    if len(sys.argv) > 1:
        python = python_environment()
        return subprocess.run([str(python), '-u', str(ROOT / 'carrier.py'), *sys.argv[1:]], cwd=ROOT).returncode
    while True:
        args = menu()
        if args is None: return 0
        if args is False: continue
        print('\n' + '─' * 56, flush=True)
        try:
            if python is None: python = python_environment()
            result = subprocess.run([str(python), '-u', str(ROOT / 'carrier.py'), *args], cwd=ROOT)
            if result.returncode == 2:
                print('\nВыбор профиля не подтверждён. Подробности — в журнале операции.')
            elif result.returncode:
                print('\nДействие не завершено. Причина указана выше.')
        except Exception as error:
            print('\nОшибка запуска:', error)
        input('\nНажмите Enter, чтобы вернуться в главное меню…')


if __name__ == '__main__':
    try: sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print('\nЗапуск прерван. Если запись уже началась, сохраните runs и используйте восстановление.')
        sys.exit(130)
    except Exception as error:
        print('Ошибка запуска:', error, file=sys.stderr)
        sys.exit(1)
