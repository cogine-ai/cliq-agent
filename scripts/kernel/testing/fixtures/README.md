`installed-status-5ad50f3.ts.fixture` is qualification data copied byte for byte
from `src/state/installed-genesis.test.ts` in commit
`5ad50f301bf5f38a673652f664e053464f75996d`, Git blob
`01571738ea145c92600ea4bd2190d7389e189b7b`. It is 16,265 bytes with SHA-256
`9b610c47d9887e3eb827d6d9c8c240b6cdaaef3d10a4fad021e70c0aee52a096`.

The fixed status-regression driver copies these original bytes into its new
archive of baseline `b6140b57836e19b0fb937327af449e8138f47eca`, at the original
source path so its imports resolve against that baseline's installation layout.
It builds the actual baseline and accepts only the original named five-second
status assertion with one failed test and every other closed count unchanged.
Missing APIs, build errors, other failures and changed bytes still refuse.
The workflow explicitly fetches that baseline if missing; the driver performs
no network access. This file is not a production compatibility path.

Today's `src/state/installed-genesis.test.ts` evolves with the current installer,
including its single-CAS data layout. Its ordinary candidate GREEN validation
remains separate. Historical RED proves the original status deadlock and does
not claim that old and current installation fixtures are generally equivalent.
