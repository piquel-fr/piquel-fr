# Build browser assets before compiling the single auth executable.
build:
    pnpm build
    cargo build --release -p auth-service

format:
    cargo fmt --all

lint:
    cargo clippy --workspace --all-targets
    pnpm check

check:
    cargo check --workspace --all-targets

test:
    cargo nextest run --workspace

# TEST_DATABASE_URL must identify a disposable local database.
test-database:
    test -n "${TEST_DATABASE_URL:?Set a disposable TEST_DATABASE_URL}"
    cargo nextest run -p auth-service -p piquel-repository --run-ignored all

migrate:
    cargo run -p auth-service -- migrate

audit:
    cargo deny check advisories licenses
    pnpm audit

# Deploy the local branch configured in infra/dev.toml.
dev:
    piquelctl --timeout 20m app deploy piquel-fr-dev --yes

# Register the development application once, then deploy it.
dev-init: (init "piquel-fr-dev" "infra/dev.toml")

# Register an application once, generating its secrets, then deploy it.
init name manifest:
    piquelctl app apply --file {{manifest}} --yes
    node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))" \
        | piquelctl app secret {{name}} set database-password --stdin --yes
    node -e "process.stdout.write(require('crypto').generateKeyPairSync('rsa', {modulusLength: 3072}).privateKey.export({type: 'pkcs8', format: 'pem'}))" \
        | piquelctl app secret {{name}} set signing-key --stdin --yes
    piquelctl --timeout 20m app deploy {{name}} --yes
