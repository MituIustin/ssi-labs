with open("input.txt", "w") as f:
    for i in range(10_000_000):
        f.write(f"photon{i}\n")