int wiener_setup(void)
{
  return 0;
}

int wiener_teardown(void)
{
  return 0;
}



struct qa_question q_wiener = {
  .name = "Wiener",
  -question_setup = wiener_setup,
};
