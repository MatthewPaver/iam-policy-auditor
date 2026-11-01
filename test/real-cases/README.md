# Public real-case regression suite

Fixtures are public AWS managed policies (see `fixtures/SOURCE.md`) or modelled from public descriptions.

## Omitted

- **C19**: SCPs are out of scope. Intersection semantics cannot be expressed by merging SCP Allow statements into an identity document.

## Results

| Case | Kind | Expected | Got | Match |
| --- | --- | --- | --- | --- |
| C01 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C01b | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C02 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C03 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C03b | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C04 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C05 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C06 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C07 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C08 | real | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C10a | real | ImplicitDeny → ImplicitDeny, pass | ImplicitDeny → ImplicitDeny, pass | yes |
| C10b | real | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C11a | real | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C11b | real | ImplicitDeny → ImplicitDeny, stop | ImplicitDeny → ImplicitDeny, stop | yes |
| C12 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C13 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C14 | modelled | ExplicitDeny → Allow, stop | ExplicitDeny → Allow, stop | yes |
| C15 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C16 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C17 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C17b | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C18 | modelled | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |
| C20a | real | ImplicitDeny → ImplicitDeny, pass | ImplicitDeny → ImplicitDeny, pass | yes |
| C20b | real | ImplicitDeny → Allow, stop | ImplicitDeny → Allow, stop | yes |

