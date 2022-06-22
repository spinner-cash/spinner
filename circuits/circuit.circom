include "./transaction.circom";

// zeroLeaf = Poseidon(zero, zero)
// default `zero` value is keccak256("tornado") % FIELD_SIZE = 21663839004416932945382355908790599225266501822907911457504978515578255421292
component main { public [root, inputNullifier, outputCommitment, publicAmount, extDataHash] } = Transaction(20, 2, 2, 11850551329423159860688778991827824730037759162201783566284850822760196767874);
