# Реализация RSA алгоритма шифрования

import random
from collections import namedtuple

def get_primes(start, stop):
    """Возвращает массив простых чисел в диапазоне ``range(start, stop)``."""
    if start >= stop:
        return []

    primes = [2]

    for n in range(3, stop + 1, 2):
        for p in primes:
            if n % p == 0:
                break
        else:
            primes.append(n)

    while primes and primes[0] < start:
        del primes[0]

    #print(primes)
    return primes


def are_relatively_prime(a, b):
    """Возвращает ``True``, если ``a`` и ``b`` являются двумя относительно простыми числами.

    Два числа являются относительно простыми, если у них нет общих множителей,
    т.е. нет целого числа (кроме 1), которое делило бы оба.
    """
    for n in range(2, min(a, b) + 1):
        if a % n == b % n == 0:
            return False
    return True


def make_key_pair(length):
    """Создает пару публичного и приватного ключей.

    Пара ключей генерируется из двух случайных простых чисел. Аргумент
    ``length`` определяет битовую длину числа ``n``,
    разделяемого между двумя ключами: чем выше, тем лучше.
    """
    if length < 4:
        raise ValueError('cannot generate a key of length less '
                         'than 4 (got {!r})'.format(length))

    # Первый шаг: поиск числа ``n`` являющегося произведением двух простых
    # чисел (``p`` и ``q``). ``n`` должно иметь число бит, определенных параметром
    # ``length``, следовательно, оно должно быть в ``range(n_min, n_max + 1)``.
    n_min = 1 << (length - 1)
    n_max = (1 << length) - 1

    # Ключ надежнее если ``p`` и ``q`` имеют одинаковую битовую длинну. Мы
    # два простых числа в диапазоне ``range(start, stop)`` так что
    # разница в их битовых длинах не больше двух 2.
    start = 1 << (length // 2 - 1)
    stop = 1 << (length // 2 + 1)
    primes = get_primes(start, stop)

    while primes:
        p = random.choice(primes)
        primes.remove(p)
        q_candidates = [q for q in primes
                        if n_min <= p * q <= n_max]
        if q_candidates:
            q = random.choice(q_candidates)
            break
    else:
        raise AssertionError("cannot find 'p' and 'q' for a key of "
                             "length={!r}".format(length))

    # Второй шаг: выбираем число ``e`` меньше чем ``(p - 1) * (q - 1)``
    # который не имеет общих факторов с ``(p - 1) * (q - 1)``.
    stop = (p - 1) * (q - 1)
    for e in range(3, stop, 2):
        if are_relatively_prime(e, stop):
            break
    else:
        raise AssertionError("cannot find 'e' with p={!r} "
                             "and q={!r}".format(p, q))

    # Шаг три: ищем ``d`` такое что ``(d * e - 1)`` далится на
    # ``(p - 1) * (q - 1)``.
    for d in range(3, stop, 2):
        if d * e % stop == 1:
            break
    else:
        raise AssertionError("cannot find 'd' with p={!r}, q={!r} "
                             "and e={!r}".format(p, q, e))

    # Возвращаем приватный и публичный ключи
    return PublicKey(p * q, e), PrivateKey(p * q, d)


class PublicKey(namedtuple('PublicKey', 'n e')):
    """Публичный ключ для шифрования данных."""

    __slots__ = ()

    def encrypt(self, x):
        """Шифруем число ``x``.

        Результатом является число, которое может быть расшифровано
        только с использованием приватного ключа
        """
        return pow(x, self.e, self.n)


class PrivateKey(namedtuple('PrivateKey', 'n d')):
    """Приватный ключ, который может быть использован для расшифровки данных."""

    __slots__ = ()

    def decrypt(self, x):
        """Дешифруем число ``x``.

        Аргумент ``x`` должен быть результатом работы ``encrypt`` метода публичного ключа.
        """
        return pow(x, self.d, self.n)


if __name__ == '__main__':
    # Тест с известными результатами.
    public = PublicKey(n=2534665157, e=7)
    private = PrivateKey(n=2534665157, d=1810402843)

    # Если поменять арнумент метода encrypt или число справа от оператора сравнения assert выдаст ошибку
    assert public.encrypt(123) == 2463995467, "Неверно"
    assert public.encrypt(456) == 2022084991, "Неверно"
    assert public.encrypt(123456) == 1299565302, "Неверно"

    assert private.decrypt(2463995467) == 123, "Неверно"
    assert private.decrypt(2022084991) == 456, "Неверно"
    assert private.decrypt(1299565302) == 123456, "Неверно"

    # Тест со случайными значениями.
    print("x" + "\t" + "y")
    for length in range(4, 17):
        public, private = make_key_pair(length)

        assert public.n == private.n
        assert len(bin(public.n)) - 2 == length

        x = random.randrange(public.n - 2)
        y = public.encrypt(x)
        print(x, end = "\t")
        print(y)

        # Проверяем сгенерированные x и y, видим что ошибок нет
        assert private.decrypt(y) == x, "Неверно"

        assert public.encrypt(public.n - 1) == public.n - 1, "Неверно"
        assert public.encrypt(public.n) == 0, "Неверно"

        assert private.decrypt(public.n - 1) == public.n - 1, "Неверно"
        assert private.decrypt(public.n) == 0, "Неверно"