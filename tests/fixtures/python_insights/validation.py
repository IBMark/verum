"""Transfer endpoint - assert-validation next to checks that survive -O."""


def create_transfer(request, ledger):
    assert request.form["amount"].isdigit()
    return ledger.enqueue(request.form)


def update_limits(params, store):
    assert params["limit"] > 0, "limit must be positive"
    return store.save(params)


def create_transfer_checked(request, ledger):
    if not request.form["amount"].isdigit():
        raise ValueError("amount must be a number")
    return ledger.enqueue(request.form)


def narrow(request):
    assert request is not None
    return request.form


def internal_invariant(batch):
    assert len(batch) > 0
    return batch[0]
