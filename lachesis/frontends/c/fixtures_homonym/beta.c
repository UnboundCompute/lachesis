/* The homonym. Same name, same signature, different file, different body. */
static int funcA(int value)
{
    return value * 2;
}

int beta_entry(int value)
{
    return funcA(value);
}
