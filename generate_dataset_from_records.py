import hashlib

word_freq = {
    "2001": 246613,
    "pst": 218860,
    "2000": 208551,
    "call": 102807,
    "thu": 93835,
    "question": 83882,
    "follow": 75409,
    "regard": 68923,
    "contact": 60270,
    "energi": 54090,
    "current": 47707,
    "legal": 39923,
    "problem": 31282,
    "industri": 21472,
    "transport": 12879,
    "target": 7311,
    "exactli": 4644,
    "enterpris": 3130
}

with open("sse_data_test", "w") as f:
    f.write(str(len(word_freq.keys())) + "\n")
    for _k in word_freq.keys():
        f.write(_k + "\n")
        f.write(str(word_freq[_k]) + "\n")
        for i in range(word_freq[_k]):
            f.write(hashlib.sha256((_k+str(i)).encode()).hexdigest()[:10] + "\n")
