function shouldShowInitialWindow(argv) {
  return !argv.includes('--smoke-test') && !argv.includes('--minimized');
}

module.exports = { shouldShowInitialWindow };
