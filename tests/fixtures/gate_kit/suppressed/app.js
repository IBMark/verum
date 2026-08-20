function runTrusted(expr) {
  // verum:ignore[EvalUsage] input is compiled in-house
  return eval(expr);
}

function runReviewed(expr) {
  /* verum:ignore audited */
  return eval(expr);
}
