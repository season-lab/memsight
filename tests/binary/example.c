int g(char * f, int i, int j) {

	char * x = &f[i];
	char * y = &f[j];
	if (f[j] == 0)
		if (f[i] == 0)
			return 0;
		else
			return 1;
	else
		return 2;
}
