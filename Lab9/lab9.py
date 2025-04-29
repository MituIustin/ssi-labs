
L = int(input("LFSR len: "))

coeff = [int(x) for x in input(f"c0, c1, ... c{L}:\n").split()]
state = [int(x) for x in input(f"s0, s1, ... s{L-1}:\n").split()]
print()

coeff.reverse()

init_state = state[:]
output = []
period = 0

while True:
    output.append(state[0])

    feedback_bit = 0
    for i in range(L-1, -1, -1):
        feedback_bit ^= coeff[i] * state[i]

    state = state[1:] + [feedback_bit]

    period += 1
    print(state)

    if state == init_state:
        output.append(state[0])
        break

print(''.join(str(bit) for bit in output))
print(f"\nperiod: {period}")

