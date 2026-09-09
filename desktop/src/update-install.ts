/**
 * Serializes the webview side of installation. Keeping this sequence explicit
 * makes it impossible for locking to overtake a pending note or canvas write.
 */
export async function prepareUpdaterInstall(
  saveNote: () => Promise<boolean>,
  flushCanvas: () => Promise<void>,
  lockVault: () => Promise<void>,
) {
  if (!(await saveNote())) {
    throw new Error("The open note could not be saved. Installation was stopped and your edits remain open.");
  }
  await flushCanvas();
  await lockVault();
}
