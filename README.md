# Spinner

The Spinner project (https://spinner.cash) takes a privacy first approach to protect users crypto assets.

It is a layer-2 protocol built on the [Internet Computer] with the following features:

- Private transactions for ICP (and soon BTC).
- Shield: deposit public tokens to a private ledger, which records only hashes, not user address, not even the amount of tokens.
- Unshield: withdraw shielded tokens to the public ledger, without revealing sender's identity.
- Fully private transfers of shielded tokens.
- Secure and verifiable deployment by construction (via [LaunchTrail]).
- Private exchange between shielded tokens (coming soon).
- Fully autonomous and owned by DAO (comming soon).

## How it works

Spinner is in [beta testing](https://spnr.app).
It does not require any wallet or login.
Simply send a small amount of ICP to the public deposit address (which is randomly generated from your browser) to start using it.

To understand how Spinner works, please check out the [explainer video](https://vimeo.com/722805939) we prepared for the [Supernova Hackathon](https://devpost.com/software/spinner-cash).

## For developers

You are welcome to checkout our source code and deploy locally.
You will need the following tools installed before you start:

- Rust toolchain, for example, [rustup].
- Javascript: [nodejs], [yarn].
- Internet Computer [SDK] and [ic-repl].
- Utilities: [GNU make], [binaryen], [jq], and other standard utilities like curl, awk, shasum, etc.

To install and compile everything:

```
yarn install --pure-lockfile
make -C data && make -C circuits && make -C actors
```

To deploy a version of Spinner locally, you have to go into the *actors* directory, and start `dfx`:

```
cd actors
make dfx.json && dfx start --background
```

Then you can deploy by installing all canisters (still in the *actors* directory):

```
make deploy MODE=install
```

This will download [LaunchTrail], install a local copy, and use it to install everything else.
Once it is done, you can continue to use the regular `dfx` command to make calls to canisters.
But all administrative operations will have to go through LaunchTrail.

Please feel free to submit bug reports or feature requests on Github.

Unless otherwise noted, all source codes are original and released under [GPLv3](./LICENSE).
Please make sure you understand the requirement and risk before using them in your own projects.

[rustup]: https://rustup.rs
[SDK]: https://github.com/dfinity/sdk
[GNU make]: https://www.gnu.org/software/make
[ic-repl]: https://github.com/chenyan2002/ic-repl
[binaryen]: https://github.com/WebAssembly/binaryen
[Internet Computer]: https://internetcomputer.org
[jq]: https://stedolan.github.io/jq/
[yarn]: https://yarnpkg.com/cli/node
[nodejs]: https://nodejs.org/
[LaunchTrail]: https://github.com/spinner-cash/launchtrail
