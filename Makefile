# The same checks CI runs, split so one kind can run alone.
#
# `test-seams` is on throughout: the `nd7_exec` and `nd7_exec_e2e` tests need
# it, and clippy has to see the code behind it.
#
# The tests cannot run inside an nd7 session. Seatbelt refuses a second
# profile, and `nd7-exec` sees itself already confined and skips the session
# lookup, so every kernel and end-to-end test fails for that one reason.
# `nd7 run` sets `ND7_SESSION`, and the test targets refuse when it is set.

FEATURES := --features test-seams

.PHONY: check fmt fmt-fix clippy clippy-fix test unit integration e2e outside-session

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

## Fails with one line when run from inside an nd7 session; see the top.
outside-session:
	@test -z "$$ND7_SESSION" || { \
		echo "make: the tests cannot run inside an nd7 session; use a plain terminal" >&2; \
		exit 1; \
	}

## Every test: unit, integration and end-to-end.
test: outside-session
	cargo test $(FEATURES)

## Unit tests only: the `#[cfg(test)]` modules in the library and binaries.
unit: outside-session
	cargo test $(FEATURES) --lib --bins

## The files under `tests/`, which drive the built binaries.
integration: outside-session
	cargo test $(FEATURES) --test '*'

## The two that run `nd7-exec` and `nd7 run` against a scratch `~/.nd7`.
e2e: outside-session
	cargo test $(FEATURES) --test nd7_exec --test nd7_exec_e2e
