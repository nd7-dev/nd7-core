# The same checks CI runs, split so one kind can run alone.
#
# `test-seams` is on throughout: the `nd7_exec` and `nd7_exec_e2e` tests need
# it, and clippy has to see the code behind it. The kernel tests in
# `src/policy.rs` fail from inside an nd7 session, because Seatbelt refuses a
# second profile; run them from a plain terminal.

FEATURES := --features test-seams

.PHONY: check fmt fmt-fix clippy clippy-fix test unit integration e2e

## Everything CI runs, in CI's order.
check: fmt clippy test

## Formatting, as a check only.
fmt:
	cargo fmt --check

## Reformat in place.
fmt-fix:
	cargo fmt

## Lints over the library, both binaries and every test, warnings as errors.
clippy:
	cargo clippy --all-targets $(FEATURES) -- -D warnings

## Apply clippy's mechanical fixes. Read the diff afterwards.
clippy-fix:
	cargo clippy --fix --allow-dirty --all-targets $(FEATURES)

## Every test: unit, integration and end-to-end.
test:
	cargo test $(FEATURES)

## Unit tests only: the `#[cfg(test)]` modules in the library and binaries.
unit:
	cargo test $(FEATURES) --lib --bins

## The files under `tests/`, which drive the built binaries.
integration:
	cargo test $(FEATURES) --test '*'

## The two that run `nd7-exec` and `nd7 run` against a scratch `~/.nd7`.
e2e:
	cargo test $(FEATURES) --test nd7_exec --test nd7_exec_e2e
