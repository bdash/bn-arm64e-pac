use binaryninja::{
    architecture::Architecture,
    logger::Logger,
    low_level_il::{
        LowLevelILRegister,
        expression::{
            ExpressionHandler, LowLevelILExpression, ValueExpr,
        },
        function::{FunctionForm, FunctionMutability},
        instruction::{
            InstructionHandler, LowLevelILInstruction,
            LowLevelInstructionIndex,
        },
        lifting::LowLevelILLabel,
    },
    rc::Ref,
    workflow::{Activity, AnalysisContext, Workflow},
};
use log::LevelFilter;

mod llil;

const ARM64E_PAC_ACTIVITY_NAME: &str = "bdash.arm64e-pac";
const ARM64E_PAC_ACTIVITY_CONFIG: &str = r#"{
    "name" : "bdash.arm64e-pac",
    "title" : "Remove explicit arm64e PAC checks",
    "description": "Remove the explicit arm64e pointer authentication checks the compiler emits prior to tail calls.",
    "eligibility": {
        "auto": {}
    }
}"#;

// Match `if ((<reg> & 0x40000000) == 0)`
// Returns `<reg>` and the operation coresponding to the `if`.
fn candidate_pac_check_register_from_if<'func, A, M, F>(
    instr: &'func LowLevelILInstruction<'func, A, M, F>,
) -> Option<(
    LowLevelILRegister<A::Register>,
    LowLevelILInstruction<'func, A, M, F>,
)>
where
    A: 'func + Architecture,
    M: FunctionMutability,
    F: FunctionForm,
    LowLevelILInstruction<'func, A, M, F>: InstructionHandler<'func, A, M, F>,
    LowLevelILExpression<'func, A, M, F, ValueExpr>: ExpressionHandler<'func, A, M, F>,
{
    use llil::{BinaryExpression, Expression::*, Instruction::*};
    let If(CmpE(cmp), true_target, ..) = instr.into() else {
        return None;
    };

    let BinaryExpression(And(and), Const(0)) = *cmp else {
        return None;
    };

    let BinaryExpression(Reg(reg), Const(0x40000000)) = *and else {
        return None;
    };

    return Some((reg, true_target));
}

// Match `<reg_a> = <reg_b> ^ (<reg_b> << 1)`
fn is_explicit_pac_check<'func, A, M, F>(
    instr: &'func LowLevelILInstruction<'func, A, M, F>,
    register: LowLevelILRegister<A::Register>,
) -> bool
where
    A: 'func + Architecture + std::fmt::Debug,
    M: FunctionMutability + std::fmt::Debug,
    F: FunctionForm + std::fmt::Debug,
    LowLevelILInstruction<'func, A, M, F>: InstructionHandler<'func, A, M, F>,
    LowLevelILExpression<'func, A, M, F, ValueExpr>: ExpressionHandler<'func, A, M, F>,
{
    use llil::{BinaryExpression, Expression::*, Instruction::*};

    let xor = match instr.into() {
        SetReg(dest, Xor(xor)) if dest == register => xor,
        _ => return false,
    };
  
    let BinaryExpression(Reg(left_reg), Lsl(lsl)) = *xor else {
        return false;
    };

    match *lsl {
        BinaryExpression(Reg(shifted_reg), Const(1)) => return left_reg == shifted_reg,
        _ => return false,
    };
}

fn process_arm64e_pac(analysis_context: &AnalysisContext) {
    let Some(llil) = (unsafe { analysis_context.llil_function() }) else {
        return;
    };

    let func = analysis_context.function();
    for basic_block in &func.basic_blocks() {
        for addr in basic_block.iter() {
            let Some(instr) = llil.instruction_at(addr) else {
                continue;
            };

            let Some((register, true_target)) = candidate_pac_check_register_from_if(&instr) else {
                continue;
            };
            let Some(prev) =
                llil.instruction_from_index(LowLevelInstructionIndex(instr.index.0 - 1))
            else {
                continue;
            };
            if !is_explicit_pac_check(&prev, register) {
                continue;
            }

            log::debug!(
                "Disabling explicit PAC check at {:#0x}-{:#0x}",
                prev.address(),
                instr.address()
            );

            if true_target.index == instr.index.next() {
                // Branch target is next instruction so we can replace the `if` with a `nop`.
                unsafe {
                    llil.replace_expression(instr.expr_idx(), llil.nop());
                };
            } else {
                // Target is further afield so we replace the `if` with a `goto`.
                let mut label = llil
                    .label_for_address(true_target.address())
                    .unwrap_or_else(|| {
                        let mut label = LowLevelILLabel::new();
                        label.operand = true_target.index.0;
                        label
                    });
                unsafe {
                    llil.replace_expression(prev.expr_idx(), llil.goto(&mut label));
                };
            }

            // `xor` is always replaced with a `nop`.
            unsafe {
                llil.replace_expression(prev.expr_idx(), llil.nop());
            }
            llil.generate_ssa_form();
        }
    }

    analysis_context.set_lifted_il_function(&llil);
}

fn register_activity(workflow: Ref<Workflow>) {
    let workflow = workflow.clone_to(workflow.name());
    let activity = Activity::new_with_action(ARM64E_PAC_ACTIVITY_CONFIG, process_arm64e_pac);
    workflow.register_activity(&activity).unwrap();
    workflow.insert(
        "core.function.generateMediumLevelIL",
        [ARM64E_PAC_ACTIVITY_NAME],
    );
    workflow.register().unwrap();
}

#[unsafe(no_mangle)]
pub extern "C" fn CorePluginDependencies() {
    use binaryninja::add_optional_plugin_dependency;
    add_optional_plugin_dependency("workflow_objc");
    add_optional_plugin_dependency("sharedcache");
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("arm64 PAC")
        .with_level(LevelFilter::Debug)
        .init();

    register_activity(Workflow::instance("core.function.metaAnalysis"));
    register_activity(Workflow::instance("core.function.objectiveC"));
    register_activity(Workflow::instance("core.function.sharedCache"));

    true
}
