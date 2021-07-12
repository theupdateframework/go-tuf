# Delegation tree
#
#             Targets
#             /     \
#            a       f
#           / \
#          b   e
#         / \
#        c   d
#
# No terminating delegations.
#
# Roles should be evaluated in the order:
# Targets > a > b > c > d > e > f

from fixtures.builder import FixtureBuilder


def build():
    FixtureBuilder('TUFTestFixture3LevelDelegation')\
        .publish(with_client=True)\
        .create_target('targets.txt')\
        .delegate('a', ['*.txt'])\
        .create_target('a.txt', signing_role='a')\
        .delegate('b', ['*.txt'], parent='a') \
        .create_target('b.txt', signing_role='b') \
        .delegate('c', ['*.txt'], parent='b') \
        .create_target('c.txt', signing_role='c') \
        .delegate('d', ['*.txt'], parent='b') \
        .create_target('d.txt', signing_role='d') \
        .delegate('e', ['*.txt'], parent='a') \
        .create_target('e.txt', signing_role='e') \
        .delegate('f', ['*.txt']) \
        .create_target('f.txt', signing_role='f') \
        .publish()
