
export function authorizeModification(req, res, next) {
  const isParent = req.user.role === "parent";
  const isOwnList =
    req.user.role === "child" &&
    String(req.params.userId) === String(req.user.id);

  if (!isParent && !isOwnList) {
    return res.status(403).json({ error: "Access denied" });
  }

  next();
}
