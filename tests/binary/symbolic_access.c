int foo(int * p, int x) {
	*p = x;
	return *p;
}

int main() {
	int * p;
	if (p < 10000 || p >= 10002) return -1;
	foo(p, 10);
	return 0;
}
