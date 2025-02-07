/*******************************************************************\

Module: Command Line Parsing

Author: Daniel Kroening, kroening@kroening.com

\*******************************************************************/

#ifndef CPROVER_GOTO_INSTRUMENT_GOTO_INSTRUMENT_PARSE_OPTIONS_H
#define CPROVER_GOTO_INSTRUMENT_GOTO_INSTRUMENT_PARSE_OPTIONS_H

#include <util/ui_message.h>
#include <util/parse_options.h>

#include <langapi/language_ui.h>
#include <goto-programs/goto_functions.h>
#include <goto-programs/show_goto_functions.h>

#include <analyses/goto_check.h>

#define GOTO_INSTRUMENT_OPTIONS \
  "(all)" \
  "(document-claims-latex)(document-claims-html)" \
  "(document-properties-latex)(document-properties-html)" \
  "(dump-c)(dump-cpp)(use-system-headers)(dot)(xml)" \
  OPT_GOTO_CHECK \
  /* no-X-check are deprecated and ignored */ \
  "(no-bounds-check)(no-pointer-check)(no-div-by-zero-check)" \
  "(no-nan-check)" \
  "(remove-pointers)" \
  "(no-simplify)" \
  "(assert-to-assume)" \
  "(no-assertions)(no-assumptions)(uninitialized-check)" \
  "(race-check)(scc)(one-event-per-cycle)" \
  "(minimum-interference)" \
  "(mm):(my-events)" \
  "(unwind):(unwindset):(unwindset-file):" \
  "(unwinding-assertions)(partial-loops)(continue-as-loops)" \
  "(log):" \
  "(max-var):(max-po-trans):(ignore-arrays)" \
  "(cfg-kill)(no-dependencies)(force-loop-duplication)" \
  "(call-graph)" \
  "(no-po-rendering)(render-cluster-file)(render-cluster-function)" \
  "(nondet-volatile)(isr):" \
  "(stack-depth):(nondet-static)" \
  "(function-enter):(function-exit):(branch):" \
  OPT_SHOW_GOTO_FUNCTIONS \
  "(show-value-sets)" \
  "(show-global-may-alias)" \
  "(show-local-bitvector-analysis)(show-custom-bitvector-analysis)" \
  "(show-escape-analysis)(escape-analysis)" \
  "(custom-bitvector-analysis)" \
  "(show-struct-alignment)(interval-analysis)(show-intervals)" \
  "(show-uninitialized)(show-locations)" \
  "(full-slice)(reachability-slice)(slice-global-inits)" \
  "(inline)(partial-inline)(function-inline):(log):(no-caching)" \
  "(remove-function-pointers)" \
  "(show-claims)(show-properties)(property):" \
  "(show-symbol-table)(show-points-to)(show-rw-set)" \
  "(cav11)" \
  "(show-natural-loops)(accelerate)(havoc-loops)" \
  "(error-label):(string-abstraction)" \
  "(verbosity):(version)(xml-ui)(json-ui)(show-loops)" \
  "(accelerate)(constant-propagator)" \
  "(k-induction):(step-case)(base-case)" \
  "(show-call-sequences)(check-call-sequence)" \
  "(interpreter)(show-reaching-definitions)(count-eloc)(list-eloc)" \
  "(list-symbols)(list-undefined-functions)" \
  "(z3)(add-library)(show-dependence-graph)" \
  "(horn)(skip-loops):(apply-code-contracts)(model-argc-argv):" \
  "(show-threaded)"

class goto_instrument_parse_optionst:
  public parse_options_baset,
  public language_uit
{
public:
  virtual int doit();
  virtual void help();

  goto_instrument_parse_optionst(int argc, const char **argv):
    parse_options_baset(GOTO_INSTRUMENT_OPTIONS, argc, argv),
    language_uit(cmdline, ui_message_handler),
    ui_message_handler(cmdline, "goto-instrument"),
    function_pointer_removal_done(false),
    partial_inlining_done(false),
    remove_returns_done(false)
  {
  }

protected:
  ui_message_handlert ui_message_handler;
  virtual void register_languages();

  void get_goto_program();
  void instrument_goto_program();

  void eval_verbosity();

  void do_indirect_call_and_rtti_removal(bool force=false);
  void do_partial_inlining();
  void do_remove_returns();

  bool function_pointer_removal_done;
  bool partial_inlining_done;
  bool remove_returns_done;

  goto_functionst goto_functions;
};

#endif // CPROVER_GOTO_INSTRUMENT_GOTO_INSTRUMENT_PARSE_OPTIONS_H
