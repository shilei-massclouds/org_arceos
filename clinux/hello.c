void sbi_console_putchar(int ch);

int say_hello()
{
    sbi_console_putchar('B');
    sbi_console_putchar('\n');
    return 202;
}
