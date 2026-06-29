# End-to-End Integration Recipes

This folder contains end-to-end integration tests for real-world workflows, backed by a recipe in [ADVANCED_USAGE.md](./ADVANCED_USAGE.md). Each recipe is a self-contained integration test that can be run against a real service stack, and demonstrates how to use Edgeport to implement a complete workflow with multiple TCP protocols, including error handling, recovery, and cross-protocol consistency.

## Scope

Recipes are **integration tests** that demonstrate how to use Edgeport in a real-world workflow. They are not unit tests, and they require a real service stack to run against.

This workflow handles integration tests via Docker Compose, and can be run in CI/CD pipelines. Each recipe is a self-contained integration test that can be run against a real service stack, and demonstrates how to use Edgeport to implement a complete workflow with multiple TCP protocols, including error handling, recovery, and cross-protocol consistency.

## Contributing

New recipes are welcome! Please submit a PR with a new recipe in `ADVANCED_USAGE.md` and a corresponding integration test in this folder. Each recipe should include:
