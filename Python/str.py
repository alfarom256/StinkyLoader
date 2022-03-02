def strify(s):
    x = '{{ {} }}'.format(
        ','.join("'{}'".format(b) for b in s)
    )
    print("char str{}[] = {};".format(s, x))