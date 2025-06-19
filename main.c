#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char sp_key_buf[64] = {};
char sp_bind_key_lower[32] = {};
void sp_key(char *bind_key, char **bind_values, int *bind_len);

int argc = 0;
char **argv = NULL;

int main(int t_argc, char *t_argv[])
{
    argc = t_argc;
    argv = t_argv;

    if (argc < 2)
    {
        printf("usage: %s <filename> [whitelisted keys]", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");

    if (!f)
    {
        printf("file not found: %s", argv[1]);
        return 1;
    }

    char buf[1024] = {};
    char in_copy[1024] = {};

    char **bind_values = calloc(16, sizeof(void *));
    int n_values = 0;

    // for each line in a config

    while (fgets(buf, sizeof(buf), f))
    {
        strcpy(in_copy, buf); // save a copy in case its not a bind

        // reset our state

        n_values = 0;

        bool got_bind = false;
        bool got_key = false;

        char *bind_key = NULL;

        char *tok = strtok(buf, " \t\n\r");
        do
        {
            // if we have a token and it's not null
            if (tok == NULL)
                break;
            if (got_bind && got_key)
                bind_values[n_values++] = tok;
            else if (got_bind && !got_key)
            {
                bind_key = tok;
                got_key = true;
            } else if (!got_bind && !got_key)
                if (strcmp(tok, "bind") == 0)
                    got_bind = true;

            tok = strtok(NULL, " \t\n\r");
        } while (tok != NULL);

        if (got_bind)
        {
            // inject sp_key into the keymap
            sp_key(bind_key, bind_values, &n_values);

            printf("bind %s", bind_key);

            for (int i = 0; i < n_values; ++i)
                printf(" %s", bind_values[i]);

            printf("\r\n");
        }
        if (!got_bind)
            printf("%s", in_copy);
    }
    fclose(f);

    return 0;
}

void sp_key(char *bind_key, char **bind_values, int *bind_len)
{
    char *sp_bind_key = sp_bind_key_lower;
    int bind_key_len = strlen(sp_bind_key);

    strcpy(sp_bind_key_lower, bind_key); // bind to lower
    for (int i = 0; i < bind_key_len; i++)
        if (isupper(sp_bind_key[i]))
            sp_bind_key[i] = tolower(sp_bind_key[i]);

    if (sp_bind_key[0] == '"') // crop the quotes
        sp_bind_key++;
    if (sp_bind_key[strlen(sp_bind_key) - 1] == '"')
        sp_bind_key[strlen(sp_bind_key) - 1] = '\0';

    if (argc > 2) // check for whitelisted keys
    {
        bool forbidden = true;
        for (int i = 2; i < argc; i++)
            if (strcmp(argv[i], sp_bind_key) == 0)
            {
                forbidden = false;
                break;
            }

        if (forbidden)
            return;
    }

    memset(sp_key_buf, 0, sizeof(sp_key_buf));
    char *last_val = bind_values[*bind_len - 1];
    int last_val_len = strlen(last_val);

    if (last_val[last_val_len - 1] == '"')
    {
        last_val[last_val_len - 1] = ';';
        sprintf(sp_key_buf, "sp_%s;\"", sp_bind_key);
    } else
        sprintf(sp_key_buf, ";sp_%s;", sp_bind_key);

    bind_values[*bind_len] = sp_key_buf;

    *bind_len += 1;
}